import os
import shutil
import base64
from datetime import datetime
from typing import List

from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from fastapi.staticfiles import StaticFiles

import models
import database
import auth
import crypto_utils
import pyotp

# --- Setup ---
database.Base.metadata.create_all(bind=database.engine)

app = FastAPI(title="Digital Evidence Chain of Custody System")

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure uploads directory
UPLOAD_DIR = "uploads"
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

# Ensure System Keys
SYSTEM_KEY_FILE = "system_key.pem"
SYSTEM_PUB_FILE = "system_key_pub.pem"

if not os.path.exists(SYSTEM_KEY_FILE):
    priv, pub = crypto_utils.generate_rsa_keypair()
    with open(SYSTEM_KEY_FILE, "wb") as f:
        f.write(priv)
    with open(SYSTEM_PUB_FILE, "wb") as f:
        f.write(pub)

def get_system_public_key():
    with open(SYSTEM_PUB_FILE, "rb") as f:
        return f.read()

def get_system_private_key():
    with open(SYSTEM_KEY_FILE, "rb") as f:
        return f.read()

# --- Pydantic Models for Response ---
from pydantic import BaseModel

class UserCreate(BaseModel):
    username: str
    password: str
    role: str

class Token(BaseModel):
    access_token: str
    token_type: str
    role: str
    otp_required: bool
    otp_secret: str = None # Only for demo/initial setup display

class EvidenceResponse(BaseModel):
    id: int
    filename: str
    description: str
    upload_time: datetime
    uploader_name: str
    status: str
    original_hash: str
    approval_status: str
    lock_status: str

# --- Routes ---

@app.post("/register", status_code=201)
def register(user: UserCreate, db: Session = Depends(database.get_db)):
    # Check if user exists
    if db.query(models.User).filter(models.User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Generate keys and OTP secret
    otp_secret = pyotp.random_base32()
    hashed_pw = crypto_utils.hash_password(user.password)
    
    # Generate User RSA Keys
    priv, pub = crypto_utils.generate_rsa_keypair()
    # In real app, encrypt priv with pw. Here logic is simplified for demo.
    
    new_user = models.User(
        username=user.username,
        password_hash=hashed_pw,
        role=user.role,
        otp_secret=otp_secret,
        public_key=pub.decode('utf-8'),
        private_key_enc=priv.decode('utf-8')
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Generate Provisioning URI for QR Code
    totp = pyotp.TOTP(otp_secret)
    provisioning_uri = totp.provisioning_uri(name=user.username, issuer_name="DigitalEvidenceLab")
    
    return {"message": "User created", "otp_secret": otp_secret, "otp_uri": provisioning_uri}

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), otp_code: str = Form(None), db: Session = Depends(database.get_db)):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not crypto_utils.verify_password(user.password_hash, form_data.password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    # OTP Check
    if not otp_code:
        # If no OTP code provided, user might need to know they need it (or UI handles logic)
        # But per spec, we return success with a flag or fail?
        # Let's simple: Require OTP code in the same request or separate endpoint?
        # Usually: 1. Login (User/Pass) -> 2. OTP. 
        # But to be simple in single API call authentication:
        # We will make the UI send OTP. If not present, we return 401 with 'OTP_REQUIRED'.
        raise HTTPException(status_code=403, detail="OTP Required")

    if not auth.verify_otp(user.otp_secret, otp_code):
         raise HTTPException(status_code=400, detail="Invalid OTP Code")

    access_token = auth.create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer", "role": user.role}

@app.get("/users/me")
def read_users_me(current_user: models.User = Depends(auth.get_current_user)):
    return {
        "username": current_user.username, 
        "role": current_user.role,
        "otp_secret": current_user.otp_secret # Exposed for demo convenience
    }

@app.post("/upload_evidence")
async def upload_evidence(
    file: UploadFile = File(...), 
    description: str = Form(...),
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(database.get_db)
):
    # Authorization: Only Collector or Admin
    if current_user.role not in [models.UserRole.COLLECTOR, models.UserRole.ADMIN]:
        raise HTTPException(status_code=403, detail="Not authorized to upload evidence")

    contents = await file.read()
    
    # 1. Hashing
    file_hash = crypto_utils.calculate_file_hash(contents)
    
    # 2. Hybrid Encryption
    aes_key = crypto_utils.get_random_bytes(32)
    ciphertext, nonce, tag = crypto_utils.encrypt_data_aes(contents, aes_key)
    
    # 3. Encrypt AES Key with System Public Key
    system_pub = get_system_public_key()
    enc_aes_key = crypto_utils.encrypt_key_rsa(aes_key, system_pub)
    
    # Save Encrypted File
    filename = f"{crypto_utils.get_random_bytes(8).hex()}_{file.filename}"
    file_path = os.path.join(UPLOAD_DIR, filename)
    with open(file_path, "wb") as f:
        f.write(ciphertext)
    
    # 4. Sign the Hash (User signs the hash of the original file)
    user_priv = current_user.private_key_enc.encode('utf-8')
    signature = crypto_utils.sign_data(file_hash, user_priv)
    
    new_evidence = models.Evidence(
        filename=file.filename,
        file_path=file_path,
        description=description,
        uploader_id=current_user.id,
        original_hash=file_hash,
        encrypted_aes_key=base64.b64encode(enc_aes_key).decode('utf-8'),
        aes_nonce=base64.b64encode(nonce).decode('utf-8'),
        aes_tag=base64.b64encode(tag).decode('utf-8'),
        status="SECURE"
    )
    db.add(new_evidence)
    db.commit()
    db.refresh(new_evidence)
    
    # 5. Chain of Custody Record
    coc = models.ChainOfCustody(
        evidence_id=new_evidence.id,
        user_id=current_user.id,
        action="UPLOAD",
        details="Initial upload and encryption",
        signature=signature
    )
    db.add(coc)
    db.commit()
    
    return {"status": "success", "evidence_id": new_evidence.id}

@app.get("/evidence", response_model=List[EvidenceResponse])
def get_all_evidence(db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_user)):
    evidence_list = db.query(models.Evidence).all()
    results = []
    for e in evidence_list:
        results.append({
            "id": e.id,
            "filename": e.filename,
            "description": e.description,
            "upload_time": e.upload_time,
            "uploader_name": e.uploader.username,
            "status": e.status,
            "original_hash": e.original_hash,
            "approval_status": e.approval_status,
            "lock_status": e.lock_status
        })
    return results

@app.get("/evidence/{evidence_id}/verify")
def verify_evidence(evidence_id: int, db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_user)):
    evidence = db.query(models.Evidence).filter(models.Evidence.id == evidence_id).first()
    if not evidence:
         raise HTTPException(status_code=404, detail="Evidence not found")
         
    # Check Integrity
    if not os.path.exists(evidence.file_path):
        return {"status": "MISSING", "details": "File not found on server"}
        
    try:
        with open(evidence.file_path, "rb") as f:
            ciphertext = f.read()
            
        sys_priv = get_system_private_key()
        enc_aes_key_bytes = base64.b64decode(evidence.encrypted_aes_key)
        aes_key = crypto_utils.decrypt_key_rsa(enc_aes_key_bytes, sys_priv)
        
        nonce = base64.b64decode(evidence.aes_nonce)
        tag = base64.b64decode(evidence.aes_tag)
        plaintext = crypto_utils.decrypt_data_aes(ciphertext, aes_key, nonce, tag)
        current_hash = crypto_utils.calculate_file_hash(plaintext)
        
        is_valid = (current_hash == evidence.original_hash)
        
        # Enforce COMPROMISED status on mismatch
        if not is_valid and evidence.status != "COMPROMISED":
            evidence.status = "COMPROMISED"
            log = models.AccessLog(evidence_id=evidence.id, user_id=current_user.id, action="INTEGRITY_CHECK_FAILED", details="Hash Mismatch detected")
            db.add(log)
            db.commit()
            
        initial_coc = db.query(models.ChainOfCustody).filter(
            models.ChainOfCustody.evidence_id == evidence.id,
            models.ChainOfCustody.action == "UPLOAD"
        ).first()
        
        signature_valid = False
        if initial_coc and evidence.uploader:
             user_pub = evidence.uploader.public_key.encode('utf-8')
             signature_valid = crypto_utils.verify_signature(evidence.original_hash, initial_coc.signature, user_pub)
        
        status_msg = "VERIFIED" if is_valid and signature_valid else "TAMPERED"
        
        return {
            "status": status_msg,
            "hash_match": is_valid,
            "signature_valid": signature_valid,
            "stored_hash": evidence.original_hash,
            "computed_hash": current_hash
        }
    except Exception as e:
        # Encryption failure usually means tampering with AES data
        if evidence.status != "COMPROMISED":
            evidence.status = "COMPROMISED"
            log = models.AccessLog(evidence_id=evidence.id, user_id=current_user.id, action="INTEGRITY_CHECK_FAILED", details=f"Decryption Error: {str(e)}")
            db.add(log)
            db.commit()
        return {"status": "TAMPERED", "error": str(e), "hash_match": False}

@app.post("/evidence/{evidence_id}/tamper")
def tamper_evidence(evidence_id: int, db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_user)):
    """Demo endpoint to manually corrupt a file to demonstrate detection."""
    if current_user.role != models.UserRole.ADMIN:
         raise HTTPException(status_code=403, detail="Only Admin can simulate tampering")
         
    evidence = db.query(models.Evidence).filter(models.Evidence.id == evidence_id).first()
    if not evidence or not os.path.exists(evidence.file_path):
        raise HTTPException(status_code=404, detail="Evidence not found")
        
    with open(evidence.file_path, "ab") as f:
        f.write(b"\x00") 
        
    evidence.status = "COMPROMISED" 
    
    # Log Security Event
    log = models.AccessLog(
        evidence_id=evidence.id, 
        user_id=current_user.id, 
        action="TAMPER_SIMULATION", 
        ip_address="127.0.0.1" 
    )
    db.add(log)
    db.commit()
    
    return {"status": "success", "message": "File artificially corrupted for demo."}

@app.get("/custody/{evidence_id}")
def get_custody_chain(evidence_id: int, db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_user)):
    chain = db.query(models.ChainOfCustody).filter(models.ChainOfCustody.evidence_id == evidence_id).order_by(models.ChainOfCustody.timestamp).all()
    results = []
    for c in chain:
        # Verify this link's signature? (Optional for list view, but could show valid/invalid icon)
        # Signature is on (Hash + Action? Or just Hash?) 
        # For simplicity in this demo, signature was on Hash.
        
        user = db.query(models.User).filter(models.User.id == c.user_id).first()
        results.append({
            "action": c.action,
            "user": user.username,
            "role": user.role,
            "timestamp": c.timestamp,
            "details": c.details,
            "signature": c.signature # Return full signature
        })
    return results

@app.post("/evidence/{evidence_id}/approve")
def approve_evidence(evidence_id: int, db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_user)):
    # Authorization: Supervisor or Admin
    if current_user.role not in [models.UserRole.SUPERVISOR, models.UserRole.ADMIN]:
        raise HTTPException(status_code=403, detail="Not authorized to approve evidence")
        
    evidence = db.query(models.Evidence).filter(models.Evidence.id == evidence_id).first()
    if not evidence:
         raise HTTPException(status_code=404, detail="Evidence not found")
         
    evidence.approval_status = "APPROVED"
    
    # Add to Chain of Custody
    coc = models.ChainOfCustody(
        evidence_id=evidence.id,
        user_id=current_user.id,
        action="APPROVE",
        details="Evidence approved by supervisor",
        signature=crypto_utils.sign_data(f"APPROVE_{evidence.id}_{datetime.utcnow()}", current_user.private_key_enc.encode('utf-8'))
    )
    db.add(coc)
    db.commit()
    return {"status": "approved"}

@app.get("/evidence/{evidence_id}/analyze")
def analyze_evidence(evidence_id: int, db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_user)):
    # Authorization: Analyst, Supervisor, Admin
    if current_user.role not in [models.UserRole.ANALYST, models.UserRole.SUPERVISOR, models.UserRole.ADMIN]:
        raise HTTPException(status_code=403, detail="Not authorized to analyze evidence")
        
    evidence = db.query(models.Evidence).filter(models.Evidence.id == evidence_id).first()
    
    if not evidence:
         raise HTTPException(status_code=404, detail="Evidence not found")

    # [SECURITY] Check Self-Protection Lock
    if evidence.lock_status == "LOCKED":
        # Log the blocked attempt
        log = models.AccessLog(evidence_id=evidence.id, user_id=current_user.id, action="ACCESS_BLOCKED", details="Access denied due to active security lock", ip_address="127.0.0.1")
        db.add(log)
        db.commit()
        raise HTTPException(status_code=423, detail="RESOURCE_LOCKED: Evidence under protective lockdown due to suspicious activity.")

    if evidence.status == "COMPROMISED":
        raise HTTPException(status_code=403, detail="Access Denied: Evidence Integrity Compromised")
    
    try:
        # [SECURITY] Monitor Access Pattern
        import security_monitor
        if current_user.role != models.UserRole.ADMIN: # Skip monitor for admin to avoid lockout during demos
             is_suspicious, alert_type, severity = security_monitor.monitor_access_pattern(db, evidence.id, current_user.id)
        
             if is_suspicious:
                 # Trigger Active Defense
                 security_monitor.trigger_protection_protocol(db, evidence, alert_type, severity)
                 raise HTTPException(status_code=423, detail=f"SECURITY ALERT: {alert_type} detected. Evidence has been automatically LOCKED.")
        
        # Add to Chain of Custody (Access Log)
        data_to_sign = f"ANALYZE_{evidence.id}_{datetime.utcnow()}"
        user_priv = current_user.private_key_enc
        
        if not user_priv:
             raise Exception("User private key missing. Cannot sign access log.")

        signature = crypto_utils.sign_data(data_to_sign, user_priv.encode('utf-8'))

        coc = models.ChainOfCustody(
            evidence_id=evidence.id,
            user_id=current_user.id,
            action="ANALYZE",
            details="Evidence accessed for analysis",
            signature=signature
        )
        db.add(coc)
        
        # Log Access
        log = models.AccessLog(evidence_id=evidence.id, user_id=current_user.id, action="ACCESS_GRANTED", ip_address="127.0.0.1")
        db.add(log)
        
        db.commit()
        return {"status": "accessed", "download_url": "simulated_secure_download"}
    except HTTPException as he:
        raise he
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")

@app.delete("/evidence/{evidence_id}")
def delete_evidence(evidence_id: int, db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_user)):
    # Authorization: Admin Only
    if current_user.role != models.UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Not authorized to delete evidence")
        
    evidence = db.query(models.Evidence).filter(models.Evidence.id == evidence_id).first()
    if evidence:
        db.delete(evidence)
        db.commit()
    return {"status": "deleted"}

@app.get("/users", response_model=List[dict])
def get_all_users(db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_user)):
    if current_user.role != models.UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Not authorized")
    users = db.query(models.User).all()
    return [{"id": u.id, "username": u.username, "role": u.role} for u in users]

@app.delete("/users/{user_id}")
def delete_user(user_id: int, db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_user)):
    if current_user.role != models.UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    if current_user.id == user_id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
        
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user:
        db.delete(user)
        db.commit()
    return {"status": "deleted"}


from fastapi.responses import StreamingResponse
import report_generator

@app.get("/evidence/{evidence_id}/report")
def download_forensic_report(evidence_id: int, db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_user)):
    # Authorization: Supervisor or Admin
    if current_user.role not in [models.UserRole.SUPERVISOR, models.UserRole.ADMIN]:
        raise HTTPException(status_code=403, detail="Not authorized to generate forensic reports")

    evidence = db.query(models.Evidence).filter(models.Evidence.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")

    # 1. Fetch Chain of Custody
    coc_chain = db.query(models.ChainOfCustody).filter(models.ChainOfCustody.evidence_id == evidence_id).order_by(models.ChainOfCustody.timestamp).all()
    
    # 2. Fetch Audit Logs
    audit_logs = db.query(models.AccessLog).filter(models.AccessLog.evidence_id == evidence_id).order_by(models.AccessLog.timestamp).all()

    # 3. Perform Live Verification (Re-using verify logic logic)
    integrity_result = {
        "status": "UNKNOWN",
        "hash_match": False,
        "signature_valid": False,
        "computed_hash": "N/A"
    }
    
    if os.path.exists(evidence.file_path):
        try:
            with open(evidence.file_path, "rb") as f:
                ciphertext = f.read()
            
            sys_priv = get_system_private_key()
            enc_aes_key_bytes = base64.b64decode(evidence.encrypted_aes_key)
            aes_key = crypto_utils.decrypt_key_rsa(enc_aes_key_bytes, sys_priv)
            
            nonce = base64.b64decode(evidence.aes_nonce)
            tag = base64.b64decode(evidence.aes_tag)
            plaintext = crypto_utils.decrypt_data_aes(ciphertext, aes_key, nonce, tag)
            current_hash = crypto_utils.calculate_file_hash(plaintext)
            
            is_valid = (current_hash == evidence.original_hash)
            
            # Verify Uploader Signature
            signature_valid = False
            initial_coc = db.query(models.ChainOfCustody).filter(
                models.ChainOfCustody.evidence_id == evidence.id,
                models.ChainOfCustody.action == "UPLOAD"
            ).first()
            
            if initial_coc and evidence.uploader:
                 user_pub = evidence.uploader.public_key.encode('utf-8')
                 signature_valid = crypto_utils.verify_signature(evidence.original_hash, initial_coc.signature, user_pub)
            
            integrity_result = {
                "status": "VERIFIED" if is_valid and signature_valid else "TAMPERED",
                "hash_match": is_valid,
                "signature_valid": signature_valid,
                "computed_hash": current_hash
            }
            
        except Exception as e:
            integrity_result["status"] = "ERROR"
            integrity_result["computed_hash"] = f"Error: {str(e)}"
    else:
         integrity_result["status"] = "MISSING_FILE"

    # 4. Generate PDF
    pdf_buffer = report_generator.generate_forensic_report(evidence, coc_chain, audit_logs, integrity_result, current_user)
    
    filename = f"Forensic_Report_{evidence.id}_{datetime.utcnow().strftime('%Y%m%d')}.pdf"
    
    return StreamingResponse(
        pdf_buffer, 
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@app.post("/evidence/{evidence_id}/unlock")
def unlock_evidence(evidence_id: int, db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_user)):
    # Authorization: Only Admin can unlock
    if current_user.role != models.UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Only Admin can unlock protected evidence")
        
    evidence = db.query(models.Evidence).filter(models.Evidence.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
        
    if evidence.lock_status != "LOCKED":
         return {"message": "Evidence is not locked"}
         
    # Unlock Protocol
    evidence.lock_status = "UNLOCKED"
    
    # Resolve alerts
    alerts = db.query(models.SecurityAlert).filter(models.SecurityAlert.evidence_id == evidence_id, models.SecurityAlert.resolved == 0).all()
    for alert in alerts:
        alert.resolved = 1
        
    # Log Action
    log = models.AccessLog(
        evidence_id=evidence.id,
        user_id=current_user.id,
        action="ADMIN_UNLOCK",
        details="Security lockdown lifted by Admin",
        ip_address="127.0.0.1"
    )
    db.add(log)
    db.commit()
    
    return {"status": "unlocked", "message": "Evidence access restored."}

@app.post("/evidence/{evidence_id}/rekey")
async def rekey_evidence_service(evidence_id: int, db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_user)):
    # Authorization: Admin Only
    if current_user.role != models.UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Not authorized to re-key evidence")

    evidence = db.query(models.Evidence).filter(models.Evidence.id == evidence_id).first()
    if not evidence or not os.path.exists(evidence.file_path):
        raise HTTPException(status_code=404, detail="Evidence not found")

    # 1. Decrypt with Old Key
    try:
        with open(evidence.file_path, "rb") as f:
            ciphertext = f.read()
        
        sys_priv = get_system_private_key()
        old_enc_key = base64.b64decode(evidence.encrypted_aes_key)
        aes_key = crypto_utils.decrypt_key_rsa(old_enc_key, sys_priv)
        
        nonce = base64.b64decode(evidence.aes_nonce)
        tag = base64.b64decode(evidence.aes_tag)
        plaintext = crypto_utils.decrypt_data_aes(ciphertext, aes_key, nonce, tag)
    except Exception as e:
        raise HTTPException(status_code=500, detail="Decryption failed. Cannot re-key corrupted evidence.")

    # 2. Generate New Key
    new_aes_key = crypto_utils.get_random_bytes(32)
    new_ciphertext, new_nonce, new_tag = crypto_utils.encrypt_data_aes(plaintext, new_aes_key)
    
    # 3. Encrypt New Key
    sys_pub = get_system_public_key()
    new_enc_key_rsa = crypto_utils.encrypt_key_rsa(new_aes_key, sys_pub)

    # 4. Update File and DB
    with open(evidence.file_path, "wb") as f:
        f.write(new_ciphertext)
        
    evidence.encrypted_aes_key = base64.b64encode(new_enc_key_rsa).decode('utf-8')
    evidence.aes_nonce = base64.b64encode(new_nonce).decode('utf-8')
    evidence.aes_tag = base64.b64encode(new_tag).decode('utf-8')
    
    # Log it
    log = models.AccessLog(
        evidence_id=evidence.id,
        user_id=current_user.id,
        action="RE_KEY",
        details="Evidence re-encrypted with rotated keys",
        ip_address="127.0.0.1"
    )
    db.add(log)
    db.commit()
    
    return {"status": "success", "message": "Evidence successfully re-encrypted."}

@app.get("/stats")
def get_stats(db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_user)):
    total_users = db.query(models.User).count()
    total_evidence = db.query(models.Evidence).count()
    secure_files = db.query(models.Evidence).filter(models.Evidence.status == "SECURE").count()
    return {"users": total_users, "evidence": total_evidence, "secure": secure_files}
