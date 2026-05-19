import sys
from main import SessionLocal, User, RoleEnum, get_password_hash

def create_super_admin():
    print("--- 🛡️ Admin Account Creator ---")
    username = input("Enter Admin Username: ")
    email = input("Enter Admin Email: ")
    password = input("Enter Admin Password: ")

    db = SessionLocal()
    try:
        # Check if user already exists
        if db.query(User).filter((User.username == username) | (User.email == email)).first():
            print("❌ Error: A user with that username or email already exists.")
            return

        hashed_pwd = get_password_hash(password)
        admin_user = User(
            username=username,
            email=email,
            hashed_password=hashed_pwd,
            role=RoleEnum.admin
        )
        
        db.add(admin_user)
        db.commit()
        print(f"✅ Success! Admin account '{username}' has been securely created.")
    except Exception as e:
        print(f"❌ Error creating admin: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    create_super_admin()