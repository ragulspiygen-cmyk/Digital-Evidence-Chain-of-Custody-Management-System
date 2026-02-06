from datetime import datetime, timedelta
from sqlalchemy.orm import Session
import models

def monitor_access_pattern(db: Session, evidence_id: int, user_id: int):
    """
    Analyzes access logs to detect suspicious patterns.
    Returns (is_suspicious, alert_type, severity)
    """
    now = datetime.utcnow()
    
    # 1. RAPID ACCESS CHECK
    # Check if user has accessed this evidence > 5 times in last 1 minute
    last_minute = now - timedelta(minutes=1)
    recent_access_count = db.query(models.AccessLog).filter(
        models.AccessLog.evidence_id == evidence_id,
        models.AccessLog.user_id == user_id,
        models.AccessLog.timestamp >= last_minute
    ).count()
    
    if recent_access_count > 5:
        return True, "RAPID_ACCESS", "HIGH"

    # 2. REPEATED FAILURE CHECK (Brute Force / Tamper attempts)
    failed_checks = db.query(models.AccessLog).filter(
        models.AccessLog.evidence_id == evidence_id,
        models.AccessLog.user_id == user_id,
        models.AccessLog.timestamp >= last_minute,
        models.AccessLog.action.in_(["INTEGRITY_CHECK_FAILED", "SIGNATURE_INVALID"])
    ).count()
    
    if failed_checks > 2:
        return True, "REPEATED_AUTH_FAILURE", "CRITICAL"

    # 3. TIME ANOMALY (e.g., Access at 3 AM)
    # Simple rule: suspicious if between 1 AM and 4 AM
    # In real app, this would be based on user's baseline
    if 1 <= now.hour <= 4:
        # Check if this is normal for this user (if they have > 3 logs in this window historically)
        historic_night_access = db.query(models.AccessLog).filter(
            models.AccessLog.user_id == user_id,
            models.AccessLog.timestamp < now - timedelta(days=1)
        ).count()
        
        # If user rarely works at night, flag it
        if historic_night_access < 3: 
             return True, "ABNORMAL_TIME_ACCESS", "MEDIUM"

    return False, None, None

def trigger_protection_protocol(db: Session, evidence: models.Evidence, alert_type: str, severity: str):
    """
    Executes automated response actions: Locked status, Alert generation.
    """
    
    # 1. Create Alert
    alert = models.SecurityAlert(
        evidence_id=evidence.id,
        severity=severity,
        alert_type=alert_type,
        message=f"Automated Defense Triggered: {alert_type} detected. Evidence locked.",
        resolved=0
    )
    db.add(alert)
    
    # 2. Lock Evidence
    evidence.lock_status = "LOCKED"
    evidence.last_security_check = datetime.utcnow()
    
    # 3. Log Action
    log = models.AccessLog(
        evidence_id=evidence.id,
        user_id=None, # System Action
        action="SYSTEM_LOCKDOWN",
        details=f"Evidence locked due to {alert_type}",
        ip_address="SYSTEM"
    )
    db.add(log)
    
    db.commit()
    return alert
