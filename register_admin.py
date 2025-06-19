import sys
from pathlib import Path
import getpass
from werkzeug.security import generate_password_hash
from website import create_app, db
from website.models import Admin
from website.config import Config

# Ensure Python can find the 'website' module by adding the root folder to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

def create_admin_account():
    # Initialize Flask app context
    app = create_app()
    
    with app.app_context():
        print("\n=== Admin Account Creation ===")
        
        # 1. Verify master password
        master_pwd = getpass.getpass("Master Password: ")
        if master_pwd != Config.MAIN_ADMIN_PASSWORD:
            print("\n❌ Error: Invalid master password")
            return
        
        # 2. Get new admin details
        print("\nEnter new admin details:")
        username = input("Username: ").strip()
        
        # Check if username exists
        if Admin.query.filter_by(username=username).first():
            print(f"\n❌ Error: Username '{username}' already exists")
            return
        
        # Get password with validation
        while True:
            password = getpass.getpass("Password: ")
            confirm = getpass.getpass("Confirm Password: ")
            
            if password != confirm:
                print("❌ Passwords don't match. Try again.")
                continue
                
            if len(password) < 8:
                print("❌ Password must be at least 8 characters.")
                continue
                
            break
        
        # 3. Create admin account
        try:
            new_admin = Admin(
                username=username,
                password_hash=generate_password_hash(password)
            )
            db.session.add(new_admin)
            db.session.commit()
            print(f"\n✅ Success! Admin account created for {username}")
        except Exception as e:
            db.session.rollback()
            print(f"\n❌ Error creating account: {str(e)}")

if __name__ == '__main__':
    create_admin_account()
