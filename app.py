from flask import Flask, redirect, request, jsonify, send_file, render_template, url_for, session
from flask_cors import CORS
import webbrowser
import json
import os
import tempfile
import uuid
from datetime import datetime
from firebase_admin import db
from fpdf import FPDF, XPos, YPos
import re
import pickle
from functools import wraps  
from werkzeug.utils import secure_filename
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences

# Import Firebase Admin SDK
import firebase_admin
from firebase_admin import credentials, auth

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
app.config['UPLOAD_EXTENSIONS'] = ['.json']
app.secret_key = 'your-secret-key'  
app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
)
CORS(app)

import json as jsonlib

# Initialize Firebase Admin SDK
if not firebase_admin._apps:
    try:
        # Use service account credentials (recommended)
        cred = credentials.Certificate("E:/BS AI/FYP/venv/cloud-f4825-firebase-adminsdk-fbsvc-5037138f8a.json")
        firebase_admin.initialize_app(cred, {
            'databaseURL': 'https://cloud-f4825-default-rtdb.firebaseio.com'  # Replace with your actual database URL
        })
        print("Firebase Admin initialized with service account")
    except Exception as e:
        print(f"Firebase Admin initialization failed: {e}")

# Load CNN model and tokenizer
try:
    model_path = os.path.join(os.path.dirname(__file__), 'json_validator.h5')
    tokenizer_path = os.path.join(os.path.dirname(__file__), 'tokenizer.pkl')
    print(f"Loading model from: {model_path}")
    print(f"Loading tokenizer from: {tokenizer_path}")
    
    model = load_model(model_path)
    with open(tokenizer_path, 'rb') as f:
        tokenizer = pickle.load(f)
    MAX_SEQUENCE_LENGTH = 100
    print("Model and tokenizer loaded successfully")
except Exception as e:
    print(f"Error loading model: {e}")
    model = None
    tokenizer = None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session or not session['user'].get('admin'):
            return "Access denied", 403
        return f(*args, **kwargs)
    return decorated_function

def save_to_history(filename, result_data, pdf_filename, is_valid):
    """
    Save validation history to Firebase Realtime Database.
    Handles unauthenticated users gracefully by using 'anonymous' as user ID.
    """

    try:
        user_id = session.get('user', {}).get('uid', 'anonymous')
        history_ref = db.reference(f'users/{user_id}/history')
        new_entry = {
            'filename': filename,
            'timestamp': datetime.now().isoformat(),
            'result': result_data,
            'pdf_filename': pdf_filename,
            'is_valid': is_valid
        }
        new_entry_ref = history_ref.push(new_entry)
        print(f"History saved with key: {new_entry_ref.key}")
    except Exception as e:
        print(f"Error saving to Firebase: {e}")

@app.route('/admin_dashboard')
@admin_required
def admin_dashboard():
    return render_template('admin.html')

try:
    user_id = session.get('user', {}).get('uid', 'anonymous')
    print(f"Saving history for user: {user_id}")
    
    history_ref = db.reference(f'users/{user_id}/history')
    
    new_entry = {
        'filename': filename,
        'timestamp': datetime.now().isoformat(),
        'result': result_data,
        'pdf_filename': pdf_filename,
        'is_valid': is_valid
    }
    
    new_entry_ref = history_ref.push(new_entry)
    print(f"History saved with key: {new_entry_ref.key}")

except Exception as e:
    print(f"Error saving to Firebase: {e}")
    



@app.route('/api/history')
@login_required
def get_history():
    """Get user's validation history from Firebase"""
    try:
        user_id = session['user']['uid']
        history_ref = db.reference(f'users/{user_id}/history')
        
        # Get all history items ordered by timestamp
        snapshot = history_ref.order_by_child('timestamp').get()
        print(f"DEBUG: Fetched history snapshot: {snapshot}")
        
        if not snapshot:
            print("DEBUG: No history found for user")
            return jsonify([])
            
        history = []
        for key, value in snapshot.items():
            error_count = len(value.get('result', {}).get('errors', []))
            history.append({
                'id': key,
                'filename': value.get('filename'),
                'upload_time': value.get('timestamp'),
                'is_valid': value.get('is_valid', False),
                'pdf_url': f"/api/download/{value.get('pdf_filename', '')}",
                'error_count': error_count
            })
            
        # Reverse to show newest first
        history.reverse()
        print(f"DEBUG: Returning history: {history}")
        return jsonify(history)
        
    except Exception as e:
        print(f"ERROR in get_history: {e}")
        return jsonify({"error": str(e)}), 500

# Keep only this validate route without login_required decorator
@app.route('/api/validate', methods=['POST'])
def validate():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    filename = secure_filename(file.filename)
    if not filename.lower().endswith('.json'):
        return jsonify({"error": "Invalid file type"}), 400

    try:
        file_content = file.read().decode('utf-8')
    except UnicodeDecodeError:
        return jsonify({"error": "Invalid file encoding"}), 400

    validator = JSONValidator()
    is_valid = validator.validate(file_content)
    
    try:
        pdf_filename = generate_pdf_report(validator, filename)
        
        # Save to Firebase instead of SQLite
        save_to_history(
            filename=filename,
            result_data={
                'errors': validator.errors,
                'warnings': validator.warnings,
                'cnn_prediction': validator.cnn_prediction
            },
            pdf_filename=pdf_filename,
            is_valid=is_valid
        )
        
        return jsonify({
            "status": "success",
            "valid": is_valid,
            "errors": validator.errors,
            "warnings": validator.warnings,
            "cnn_prediction": validator.cnn_prediction,
            "pdf_url": f"/api/download/{pdf_filename}"
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": "Report generation failed",
            "details": str(e)
        }), 500

class JSONValidator:
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.valid_json = None
        self.cnn_prediction = None
        self.cnn_confidence = None
        self.original_content = ""
        self.is_valid = False

    def clean_json(self, json_str):
        """Remove comments and fix common JSON issues"""
        # Remove single and multi-line comments
        cleaned = re.sub(r'\/\/.*|\/\*.*?\*\/', '', json_str, flags=re.DOTALL)
        # Fix single quotes
        cleaned = re.sub(r"(?<!\\)'", '"', cleaned)
        # Remove trailing commas
        cleaned = re.sub(r',\s*([}\]])', r'\1', cleaned)
        return cleaned

    def validate(self, json_str):
        """Validate JSON with comprehensive error reporting"""
        self.original_content = json_str
        
        try:
            # First try parsing directly
            try:
                self.valid_json = json.loads(json_str)
                self.is_valid = True
            except json.JSONDecodeError as e:
                self._parse_syntax_error(e, json_str)
                self.is_valid = False
                
                # Try with cleaned version
                cleaned = self.clean_json(json_str)
                try:
                    self.valid_json = json.loads(cleaned)
                    self.is_valid = True
                    self.warnings.append({
                        'message': "JSON required cleaning to parse",
                        'suggestion': "Remove comments and fix formatting",
                        'error_type': "Format Warning"
                    })
                except json.JSONDecodeError as e2:
                    self._parse_syntax_error(e2, cleaned)

            self.check_common_problems(json_str)
            
            if model and tokenizer:
                self._cnn_analysis(json_str)
                
            return self.is_valid
            
        except Exception as e:
            self.errors.append({
                'message': "Validation processing error",
                'details': str(e),
                'error_type': "System Error"
            })
            return False

    def _parse_syntax_error(self, error, json_str):
        lines = json_str.split('\n')
        error_line = lines[error.lineno - 1] if error.lineno <= len(lines) else ""
        
        self.errors.append({
            'line': error.lineno,
            'column': error.colno,
            'message': error.msg,
            'context': error_line.strip(),
            'error_type': 'Syntax Error'
        })

    def check_common_problems(self, json_str):
        if re.search(r',\s*[}\]]', json_str):
            self.warnings.append({
                'message': "Trailing comma detected",
                'suggestion': "Remove trailing commas in objects/arrays",
                'error_type': "Format Warning"
            })
        if "'" in json_str:
            self.warnings.append({
                'message': "Single quotes detected",
                'suggestion': "Use double quotes for JSON strings",
                'error_type': "Format Warning"
            })
        if '//' in json_str or '/*' in json_str:
            self.warnings.append({
                'message': "Comments detected",
                'suggestion': "Remove comments (not JSON standard)",
                'error_type': "Format Warning"
            })

def cnn_analysis(self, json_str):
    if model is None or tokenizer is None:
        return

    try:
        sequence = tokenizer.texts_to_sequences([json_str])
        padded = pad_sequences(sequence, maxlen=MAX_SEQUENCE_LENGTH)
        prediction = model.predict(padded)[0][0]
        
        self.cnn_prediction = float(prediction)  # Convert to native float
        self.cnn_confidence = float(abs(prediction - 0.5) * 2)  # Convert to native float

        if prediction > 0.7:
            self.warnings.append({
                'message': "Potential structural issues detected",
                'suggestion': "Review JSON structure carefully",
                'error_type': "Structural Warning",
                'confidence': f"{self.cnn_confidence * 100:.1f}%"  # Already stringified for safety
            })
    except Exception as e:
        print(f"CNN analysis error: {e}")


from fpdf import FPDF, XPos, YPos

class PDFReport(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)
        self.set_font("Helvetica", size=12)

    def header(self):
        self.set_font('Helvetica', 'B', 16)
        # Removed duplicate title here to avoid repetition
        # self.cell(0, 10, 'JSON Validation Report', align='C', ln=True)
        self.ln(5)
        self.set_draw_color(0, 0, 0)
        self.rect(self.l_margin, self.t_margin, self.w - 2 * self.l_margin, self.h - self.t_margin - self.b_margin)

    def footer(self):
        self.set_y(-30)
        self.set_font('Helvetica', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', align='C')
        self.ln(5)
        self.set_font('Helvetica', '', 8)
        footer_text = "© 2025 Cloud Misconfiguration Detection. All rights reserved.\nSecure your cloud infrastructure with confidence."
        # Multi-cell for footer text with center alignment
        self.multi_cell(0, 5, footer_text, align='C')


def generate_pdf_report(validator, filename):
    pdf = PDFReport()
    pdf.add_page()

    # --- Cover Page ---
    pdf.set_font('Helvetica', 'B', 28)
    pdf.cell(w=0, h=20, text="CloudSecure", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
    pdf.set_font('Helvetica', 'B', 18)
    pdf.cell(w=0, h=15, text="JSON Validation Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
    pdf.ln(20)

    pdf.set_font('Helvetica', '', 12)
    pdf.cell(w=0, h=10, text=f"File: {filename}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(w=0, h=10, text=f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(20)

    # --- Validation Summary ---
    pdf.set_font('Helvetica', 'B', 16)
    pdf.cell(w=0, h=10, text="Validation Summary", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font('Helvetica', '', 12)

    if validator.is_valid:
        pdf.set_text_color(0, 128, 0)
        pdf.cell(w=0, h=10, text="Valid JSON", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    else:
        pdf.set_text_color(200, 0, 0)
        pdf.multi_cell(w=0, h=8, text=f"Invalid JSON ({len(validator.errors)} errors)")
    pdf.set_text_color(0, 0, 0)

    # --- Structural Analysis ---
    if validator.cnn_prediction is not None:
        pdf.ln(10)
        pdf.set_font('Helvetica', 'B', 14)
        pdf.cell(w=0, h=10, text="Structural Analysis", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font('Helvetica', '', 12)

        confidence = validator.cnn_confidence * 100
        if validator.cnn_prediction > 0.7:
            pdf.set_text_color(200, 0, 0)
            status = "Potential issues detected"
        elif validator.cnn_prediction < 0.3:
            pdf.set_text_color(0, 128, 0)
            status = "No structural issues"
        else:
            pdf.set_text_color(200, 100, 0)
            status = "Inconclusive analysis"

        pdf.multi_cell(w=0, h=8, text=f"Status: {status} (confidence: {confidence:.1f}%)")
        pdf.set_text_color(0, 0, 0)

    # --- Utility: Safe text wrapping ---
    def safe_text(text, max_len=500):
        text = str(text)
        # Replace carriage returns with spaces but preserve line breaks for multi_cell wrapping
        text = text.replace('\r', '')
        if len(text) > max_len:
            return text[:max_len] + '...'
        return text

    max_width = pdf.w - 2 * pdf.l_margin

    # --- Validation Errors ---
    if validator.errors:
        pdf.add_page()
        pdf.set_font('Helvetica', 'B', 16)
        pdf.cell(w=0, h=10, text="Validation Errors", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font('Helvetica', '', 10)  # Reduced font size for better fit

    for error in validator.errors:
        try:
            line = error.get('line', 'N/A')
            column = error.get('column', 'N/A')
            message = safe_text(error.get('message', 'Unknown Error'))
            context = safe_text(error.get('context', ''))
        
            pdf.multi_cell(w=max_width, h=7, text=f"Line {line}, Column {column}: {message}")
            if context:
                pdf.multi_cell(w=max_width, h=7, text=f"Context: {context}")
                pdf.ln(3)
        except Exception as e:
            fallback = safe_text(f"Error displaying error message: {str(e)}")
            pdf.multi_cell(w=max_width, h=7, text=fallback)
            pdf.ln(3)

    # --- Validation Warnings ---
    if validator.warnings:
        pdf.add_page()
        pdf.set_font('Helvetica', 'B', 16)
        pdf.cell(w=0, h=10, text="Validation Warnings", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font('Helvetica', '', 10)  # Reduced font size for better fit

        for warning in validator.warnings:
            try:
                err_type = safe_text(warning.get('error_type', 'Unknown'))
                message = safe_text(warning.get('message', ''))
                suggestion = safe_text(warning.get('suggestion', ''))
                confidence = warning.get('confidence')

                pdf.multi_cell(w=max_width, h=7, text=f"{err_type}: {message}")
                pdf.multi_cell(w=max_width, h=7, text=f"Suggestion: {suggestion}")
                if confidence:
                    #pdf.multi_cell(w=max_width, h=7, text=f"Confidence: {confidence}")
                    pdf.multi_cell(w=0, h=7, text=f"Status: {status} (confidence: {confidence:.1f}%)")
                pdf.ln(3)
            except Exception as e:
                pdf.multi_cell(w=max_width, h=7, text=f"Error displaying warning: {str(e)}")
                pdf.ln(3)

    # --- Save ---
    report_id = str(uuid.uuid4())
    pdf_path = os.path.join(tempfile.gettempdir(), f"report_{report_id}.pdf")
    pdf.output(pdf_path)
    return f"report_{report_id}.pdf"


@app.route('/')
def home():
    return render_template('fypfrontend.html')


@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')

@app.route('/signup', methods=['GET'])
def signup_page():
    return render_template('signup.html')

from firebase_admin import db

from firebase_admin import db

from flask import redirect

@app.route('/login', methods=['POST', 'OPTIONS'])
def login():
    try:
        # Get the Firebase ID token from frontend
        id_token = request.json.get('idToken')
        print(f"Received idToken: {id_token}")
        
        # Verify the token
        decoded_token = auth.verify_id_token(id_token)
        print(f"Decoded token: {decoded_token}")
        
        uid = decoded_token['uid']
        # Fetch user role (isAdmin) from the database
        user_ref = db.reference(f'users/{uid}')
        user_data = user_ref.get() or {}
        print(f"User data fetched from Firebase: {user_data}")  # Debug print
        is_admin = user_data.get('isAdmin', False)
        
        # Set session user info including admin flag
        session['user'] = {
            'uid': uid,
            'email': decoded_token.get('email', ''),
            'admin': is_admin
        }
        
        # Return JSON with redirect URL based on admin status
        if is_admin:
            return jsonify({'redirect_url': url_for('admin_dashboard')})
        else:
            return jsonify({'redirect_url': url_for('upload_page')})
        
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 401




@app.route('/logout', methods=['POST', 'OPTIONS'])
@login_required
def logout():
    # Clear the session
    session.clear()
    return jsonify({'message': 'Successfully logged out'})

@app.route('/check-auth', methods=['GET'])
def check_auth():
    """Endpoint to check if user is authenticated"""
    if 'user' in session:
        return jsonify({'authenticated': True, 'user': session['user']})
    return jsonify({'authenticated': False}), 401

@app.route('/protected-route')
@login_required
def protected_route():
    return jsonify({'message': 'This is a protected route'})

@app.route('/upload')
def upload_page():
    return render_template('fyp2.html')

@app.route('/signup')
def signup_page_render():
    return render_template('signup.html')

@app.route('/history')
@login_required
def history_page():
    return render_template('history.html')

@app.route('/about')
def about_page():
    return render_template('fyp3.html')

@app.route('/admin')
def admin_page():
    return render_template('admin.html')


@app.route('/api/download/<filename>')
def download(filename):
    pdf_path = os.path.join(tempfile.gettempdir(), filename)
    if os.path.exists(pdf_path):
        return send_file(pdf_path, as_attachment=True)
    return jsonify({"error": "File not found"}), 404

from flask import request

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def admin_get_users():
    try:
        # List all users from Firebase Authentication
        users = []
        page = auth.list_users()
        while page:
            for user in page.users:
                # Fetch isAdmin flag from Realtime Database
                user_ref = db.reference(f'users/{user.uid}')
                user_data = user_ref.get() or {}
                users.append({
                    'uid': user.uid,
                    'email': user.email,
                    'isAdmin': user_data.get('isAdmin', False)
                })
            page = page.get_next_page()
        return jsonify(users)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/users/toggle_admin', methods=['POST'])
@admin_required
def admin_toggle_admin():
    try:
        uid = request.json.get('uid')
        if not uid:
            return jsonify({'error': 'UID is required'}), 400
        user_ref = db.reference(f'users/{uid}')
        user_data = user_ref.get() or {}
        current_admin = user_data.get('isAdmin', False)
        user_ref.update({'isAdmin': not current_admin})
        return jsonify({'uid': uid, 'isAdmin': not current_admin})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/users/<uid>', methods=['DELETE'])
@admin_required
def admin_delete_user(uid):
    try:
        # Delete user from Firebase Authentication
        auth.delete_user(uid)
        # Delete user data from Realtime Database
        user_ref = db.reference(f'users/{uid}')
        user_ref.delete()
        return jsonify({'message': f'User {uid} deleted'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/uploads', methods=['GET'])
@admin_required
def admin_get_uploads():
    try:
        # List uploaded files from Firebase Realtime Database under all users
        uploads = []
        users_ref = db.reference('users')
        users = users_ref.get() or {}
        for uid, user_data in users.items():
            history = user_data.get('history', {})
            for key, entry in history.items():
                filename = entry.get('pdf_filename')
                if filename:
                    uploads.append({'filename': filename, 'user': uid})
        return jsonify(uploads)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/uploads/<filename>', methods=['DELETE'])
@admin_required
def admin_delete_upload(filename):
    try:
        # Delete the PDF file from temp directory
        pdf_path = os.path.join(tempfile.gettempdir(), filename)
        if os.path.exists(pdf_path):
            os.remove(pdf_path)
            return jsonify({'message': f'File {filename} deleted'})
        else:
            return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/model', methods=['POST'])
@admin_required
def admin_upload_model():
    try:
        if 'model-file' not in request.files:
            return jsonify({'error': 'No model file provided'}), 400
        file = request.files['model-file']
        if not file.filename.endswith('.h5'):
            return jsonify({'error': 'Invalid file type, must be .h5'}), 400
        model_path = os.path.join(os.path.dirname(__file__), 'json_validator.h5')
        file.save(model_path)
        # Reload the model
        global model
        model = load_model(model_path)
        return jsonify({'message': 'Model uploaded and reloaded successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/logs', methods=['GET'])
@admin_required
def admin_get_logs():
    try:
        # For simplicity, read last 1000 chars from a log file if exists
        log_file = 'app.log'
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(size - 1000, 0), 0)
                logs = f.read()
        else:
            logs = 'No log file found.'
        return jsonify({'logs': logs})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    webbrowser.open_new('http://127.0.0.1:5000')
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
