from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Enum
from sqlalchemy.orm import relationship
import enum
from datetime import datetime
from database import Base

class UserRole(str, enum.Enum):
    COLLECTOR = "Evidence Collector"
    ANALYST = "Forensic Analyst"
    SUPERVISOR = "Supervisor"
    ADMIN = "Admin"

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String) # Salted SHA-256
    role = Column(String) # Stored as string to simplify, validated by app
    otp_secret = Column(String)
    
    # User's RSA Keys (Public is visible, Private is encrypted by their password/system key - simplified here: stored securely)
    # in a real system, private key might be encrypted with user's password derived key. 
    # For this demo, we'll store them as text but in a real app, strict protections apply.
    public_key = Column(Text)
    private_key_enc = Column(Text) # Encrypted private key (optional implementation detail)

    evidence_uploaded = relationship("Evidence", back_populates="uploader")
    audit_logs = relationship("AccessLog", back_populates="user")

class Evidence(Base):
    __tablename__ = "evidence"
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String)
    file_path = Column(String) # Path to encrypted file on disk
    description = Column(String)
    uploader_id = Column(Integer, ForeignKey("users.id"))
    upload_time = Column(DateTime, default=datetime.utcnow)
    
    # Security Metadata
    original_hash = Column(String) # SHA-256 of the original plaintext file
    encrypted_aes_key = Column(String) # AES key encrypted with System Public Key (Base64)
    aes_nonce = Column(String) # Base64
    aes_tag = Column(String) # Base64
    
    # Tamper Detection
    status = Column(String, default="SECURE") # SECURE, COMPROMISED
    approval_status = Column(String, default="PENDING") # PENDING, APPROVED, REJECTED

    # Post-Access Protection
    lock_status = Column(String, default="UNLOCKED") # UNLOCKED, LOCKED, RE_KEYING
    last_security_check = Column(DateTime, default=datetime.utcnow)
    
    uploader = relationship("User", back_populates="evidence_uploaded")
    chain_of_custody = relationship("ChainOfCustody", back_populates="evidence")
    alerts = relationship("SecurityAlert", back_populates="evidence")

class ChainOfCustody(Base):
    __tablename__ = "chain_of_custody"
    id = Column(Integer, primary_key=True, index=True)
    evidence_id = Column(Integer, ForeignKey("evidence.id"))
    user_id = Column(Integer, ForeignKey("users.id")) # Who performed the action
    action = Column(String) # UPLOAD, ACCESS, TRANSFER, ANALYZE
    timestamp = Column(DateTime, default=datetime.utcnow)
    details = Column(String)
    
    # Digital Signature: User signs (EvidenceID + Action + Timestamp) using their Private Key
    signature = Column(String) # Base64 signature
    
    evidence = relationship("Evidence", back_populates="chain_of_custody")
    user = relationship("User")

class AccessLog(Base):
    __tablename__ = "access_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    evidence_id = Column(Integer, ForeignKey("evidence.id"), nullable=True) # Added for tamper logging
    action = Column(String)
    details = Column(String) # For security context
    timestamp = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String)
    
    user = relationship("User", back_populates="audit_logs")
    evidence = relationship("Evidence")

class SecurityAlert(Base):
    __tablename__ = "security_alerts"
    id = Column(Integer, primary_key=True, index=True)
    evidence_id = Column(Integer, ForeignKey("evidence.id"))
    severity = Column(String) # LOW, MEDIUM, HIGH, CRITICAL
    alert_type = Column(String) # RAPID_ACCESS, BAD_IP, TAMPER_ATTEMPT, FAILED_AUTH
    message = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    resolved = Column(Integer, default=0) # 0 = Active, 1 = Resolved
    
    evidence = relationship("Evidence", back_populates="alerts")
