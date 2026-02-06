
# Post-Access Evidence Self-Protection Implementation

## Overview
This update introduces a comprehensive Post-Access Evidence Self-Protection module. The system now actively monitors evidence access patterns and automatically triggers protective measures when suspicious activity is detected.

## Key Features

### 1. Real-time Access Monitoring (`security_monitor.py`)
- Analyzes access logs for three main anomaly types:
  - **Rapid Access**: Multiple access attempts within a short timeframe (e.g., >5 attempts in 10 minutes).
  - **Repeated Failures**: Consecutive failed verification or signature checks.
  - **Time Anomalies**: Access attempts during unusual hours (e.g., 23:00 - 05:00), indicating potential localized threat.
- Automatically triggers a "Protection Protocol" if anomalies exceed thresholds.

### 2. Automated Self-Protection
- **Evidence Locking**: 
  - Evidence status changes to `LOCKED` upon threat detection.
  - Access to `analyze` (decryption) is blocked for all users, including the original officer, until unlocked by an Admin.
- **Incident Logging**:
  - All suspicious events are logged in the `SecurityAlert` table.
  - Examples: "Rapid Access Detected", "Verification Failure Spike".

### 3. Secure Recovery Workflows
- **Emergency Unlock**:
  - Admins can manually unlock evidence via the Web UI (`/evidence/{id}/unlock`).
  - This action resolves all active alerts and logs an `ADMIN_UNLOCK` event.
- **Re-Encryption (Re-Key)**:
  - Admins can trigger a `RE_KEY` operation.
  - This process decrypts the file with the old key, generates a brand new AES-256 key, re-encrypts the file, and updates the key registry.
  - Useful if a key is suspected to be compromised (e.g., after an employee leaves).

### 4. Web UI Enhancements
- **Status Indicators**:
  - New "SECURITY LOCKDOWN" badge (Orange) appears when evidence is locked.
  - "TAMPER DETECTED" badge (Red) remains for integrity failures.
- **Admin Controls**:
  - **Unlock Button**: Visible only for Locked evidence.
  - **Rotate Keys Button**: New action to trigger the re-encryption workflow.
  - **Filter**: Users can filter the evidence list to show only `LOCKED` items.

## Verification
- **Test Lock**: Simulate rapid access or failed verification to trigger the lock (backend logic).
- **Test Unlock**: Use the admin dashboard to unlock the evidence.
- **Test Re-Key**: Use the "Rotate Keys" button and verify the file is still accessible (decrypts correctly).

## Future Improvements
- **IP Geolocation**: Integrate a real IP geolocation service for "Unusual Location" detection (currently a placeholder).
- **Email Alerts**: Send SMTP emails to admins when a high-severity alert is triggered.
