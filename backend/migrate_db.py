
import sqlite3

def migrate():
    db_file = 'evidence_system_v3.db'
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    
    print(f"Checking {db_file}...")
    
    # Check Evidence table columns
    cursor.execute("PRAGMA table_info(evidence)")
    columns = [row[1] for row in cursor.fetchall()]
    print(f"Current columns in evidence: {columns}")
    
    if 'lock_status' not in columns:
        print("Adding lock_status column...")
        cursor.execute("ALTER TABLE evidence ADD COLUMN lock_status VARCHAR DEFAULT 'UNLOCKED'")
    else:
        print("lock_status already exists.")

    if 'last_security_check' not in columns:
        print("Adding last_security_check column...")
        cursor.execute("ALTER TABLE evidence ADD COLUMN last_security_check DATETIME")
    else:
        print("last_security_check already exists.")
        
    conn.commit()
    conn.close()
    print("Migration complete.")

if __name__ == "__main__":
    migrate()
