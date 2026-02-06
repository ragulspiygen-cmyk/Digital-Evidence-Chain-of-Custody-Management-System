
# Start the Backend Server
Write-Host "Starting Backend Server..."
cd "c:\focs project\digital_evidence_coc\backend"

# Ensure dependencies are installed (optional, but good for safety)
# pip install -r requirements.txt

# Run Uvicorn
uvicorn main:app --reload --host 127.0.0.1 --port 8000
