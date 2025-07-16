import sys
import firebase_admin
from firebase_admin import credentials, auth, db

def initialize_firebase():
    if not firebase_admin._apps:
        cred = credentials.Certificate("E:/BS AI/FYP/venv/cloud-f4825-firebase-adminsdk-fbsvc-5037138f8a.json")
        firebase_admin.initialize_app(cred, {
            'databaseURL': 'https://cloud-f4825-default-rtdb.firebaseio.com'
        })

def set_user_admin(email):
    try:
        user = auth.get_user_by_email(email)
        uid = user.uid
        ref = db.reference(f'users/{uid}')
        ref.update({'isAdmin': True})
        print(f"User {email} (UID: {uid}) is now set as admin.")
    except Exception as e:
        print(f"Error setting admin role for {email}: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python set_admin.py user_email@example.com")
        sys.exit(1)
    email = sys.argv[1]
    initialize_firebase()
    set_user_admin(email)
