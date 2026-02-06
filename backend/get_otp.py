from sqlalchemy.orm import Session
from database import SessionLocal, engine
import models
import pyotp

# Ensure tables exist (though main app does this)
models.Base.metadata.create_all(bind=engine)

def get_otp_for_user(username):
    db = SessionLocal()
    user = db.query(models.User).filter(models.User.username == username).first()
    if user:
        totp = pyotp.TOTP(user.otp_secret)
        current_code = totp.now()
        print(f"User: {user.username}")
        print(f"OTP Secret: {user.otp_secret}")
        print(f"Current Valid Code: {current_code}")
    else:
        print(f"User {username} not found")
    db.close()

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        get_otp_for_user(sys.argv[1])
    else:
        # Default to abishek based on screenshot
        get_otp_for_user("abishek")
