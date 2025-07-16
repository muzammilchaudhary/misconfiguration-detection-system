# 🔐 Misconfiguration Detection System

An AI-powered Flask web application that scans and analyzes uploaded JSON configuration files (e.g., AWS CloudFormation templates) to detect misconfigurations using a trained CNN model. It provides validation, generates detailed PDF reports, and includes Firebase-based authentication with OTP-based 2FA.

---

## 🌟 Features

- 📁 Upload JSON-based configuration files
- 🤖 CNN-based structural misconfiguration detection
- ✅ Syntax & format validation
- 🧾 Auto-generated PDF reports (Unicode-supported)
- 🔐 Firebase Authentication with OTP (Phone-based 2FA)
- 👤 Admin view with user history tracking
- 🖼️ Intuitive Frontend using HTML & CSS

---

## 🧰 Tech Stack

- Python (Flask)
- Firebase Authentication
- TensorFlow / Keras (for CNN)
- FPDF (PDF generation)
- SQLite (local user history database)
- HTML, CSS (Frontend)

---

## 🗂️ Project Structure

├── app.py # Main Flask app
├── train_model.py # CNN training script
├── set_admin.py # Set admin status script
├── model/
│ ├── json_validator.h5 # Trained CNN model
│ └── tokenizer.pkl # Tokenizer for JSON input
├── templates/ # Frontend HTML templates
├── static/ # Static files like images
├── fonts/DejaVuSans.ttf # Font for Unicode PDF support
├── FYP DATASET/ # Sample input JSON files (with/without errors)

⚙️ How to Run Locally

Clone repo & open project folder
Create virtual environment: python -m venv venv
Activate venv: venv\Scripts\activate (Windows) or source venv/bin/activate (Linux/macOS)
Install deps: pip install -r requirements.txt
Add Firebase admin SDK JSON as firebase_admin_credentials.json in root
Enable Email/Password & Phone Auth in Firebase Console
Run the app: python app.py
Open: http://127.0.0.1:5000

!!!---------This project is open-source and licensed under the MIT License.-----------!!!
