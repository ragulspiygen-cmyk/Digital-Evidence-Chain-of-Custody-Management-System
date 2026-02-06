
from database import SessionLocal
from models import User, Evidence, AccessLog
import security_monitor

db = SessionLocal()
user = db.query(User).filter(User.username == 'abi').first()
evidence = db.query(Evidence).first()

if user and evidence:
    print(f"Testing Trigger Protection for param")
    try:
        security_monitor.trigger_protection_protocol(db, evidence, "TEST_ALERT", "LOW")
        print("Trigger Success")
    except Exception as e:
        print(f"Trigger Failed: {e}")
        import traceback
        traceback.print_exc()
