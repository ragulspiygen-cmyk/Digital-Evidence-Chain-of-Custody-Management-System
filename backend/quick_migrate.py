
import sqlite3

def add_column():
    print("Migrating Database...")
    conn = sqlite3.connect('evidence_system.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute("ALTER TABLE access_logs ADD COLUMN details TEXT")
        print("Column 'details' added successfully.")
    except sqlite3.OperationalError as e:
        print(f"Migration might have already run: {e}")
        
    conn.commit()
    conn.close()

if __name__ == "__main__":
    add_column()
