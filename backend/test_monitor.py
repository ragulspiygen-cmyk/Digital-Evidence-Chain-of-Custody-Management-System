
from database import SessionLocal
from models import User, Evidence, AccessLog
import security_monitor
from datetime import datetime

db = SessionLocal()
user = db.query(User).filter(User.username == 'abi').first()
evidence = db.query(Evidence).first()

if user and evidence:
    print(f"Testing monitor for User {user.id} Evidence {evidence.id}")
    try:
        is_suspicious, alert, sev = security_monitor.monitor_access_pattern(db, evidence.id, user.id)
        print(f"Monitor Result: {is_suspicious}, {alert}, {sev}")
    except Exception as e:
        print(f"Monitor Failed: {e}")
        import traceback
        traceback.print_exc()
else:
    print("User or Evidence not found")
