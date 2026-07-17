import urllib.request
import json
import ssl
import base64
import time
import subprocess
import sys

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# 1x1 transparent PNG base64
valid_png = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==')
screenshot_b64 = base64.b64encode(valid_png).decode()

def run_cmd(cmd):
    return subprocess.check_output(cmd, shell=True).decode().strip()

print("=======================================================================")
print("                      AEGIS PIPELINE SCANNER                           ")
print("=======================================================================")

# 1. Automatically register user if missing (returns 202 Accepted)
print("\n[1] Ensuring user account exists...")
reg_req = urllib.request.Request('https://localhost/api/auth/register', data=json.dumps({'email': 'analyst@test.com', 'password': 'TestPass123!@#'}).encode(), headers={'Content-Type': 'application/json'}, method='POST')
try:
    urllib.request.urlopen(reg_req, context=ctx)
    print("    -> User ensured/created.")
except Exception:
    print("    -> User already exists.")

# 2. Login to get JWT Token
print("\n[2] Authenticating with Nginx ingress (POST /api/auth/login)...")
login_data = 'username=analyst@test.com&password=TestPass123!@#'.encode()
req = urllib.request.Request('https://localhost/api/auth/login', data=login_data, headers={'Content-Type': 'application/x-www-form-urlencoded'}, method='POST')
try:
    auth_resp = urllib.request.urlopen(req, context=ctx)
    token = json.loads(auth_resp.read().decode())['access_token']
    print("    -> SUCCESS: JWT access token acquired.")
except Exception as e:
    print(f"    -> FATAL: Authentication failed: {e}")
    sys.exit(1)

# 3. Submit Stage 2 Scan
target_url = "https://example.com/"
print(f"\n[3] Submitting Stage 2 scan payload for: {target_url}...")
html_payload = "<html><head><title>Example Domain</title></head><body><h1>Scan Test</h1></body></html>"
stage2_payload = json.dumps({
    'url': target_url,
    'screenshot_base64': screenshot_b64,
    'html': html_payload
}).encode()

req_scan = urllib.request.Request('https://localhost/api/scans/stage2', data=stage2_payload, headers={
    'Authorization': f'Bearer {token}',
    'Content-Type': 'application/json'
}, method='POST')

try:
    scan_resp = urllib.request.urlopen(req_scan, context=ctx)
    scan_res = json.loads(scan_resp.read().decode())
    scan_id = scan_res['scan_id']
    job_id = scan_res['job_id']
    print(f"    -> SUCCESS: Scan queued instantly!")
    print(f"       Scan ID : {scan_id}")
    print(f"       Job ID  : {job_id}")
    print(f"       Status  : {scan_res['status']}")
except Exception as e:
    print(f"    -> FATAL: Scan submission failed: {e}")
    sys.exit(1)

# 4. Track progression
print(f"\n[4] Tracking progression of stages across Celery workers...")
start_time = time.time()
for _ in range(18):
    status_query = f"docker exec -u postgres aegis_postgres psql -d aegis_db -t -c \"SELECT status, risk_score, severity FROM scans WHERE id = '{scan_id}';\""
    row = run_cmd(status_query).strip()
    parts = [p.strip() for p in row.split('|')] if '|' in row else [row]
    current_status = parts[0] if parts else "unknown"
    score = parts[1] if len(parts) > 1 else ""
    sev = parts[2] if len(parts) > 2 else ""
    
    elapsed = int(time.time() - start_time)
    print(f"    [{elapsed:02d}s] Status: {current_status:<25} | score: {score:<6} | severity: {sev}")
    
    if current_status in ["risk_fusion_done", "risk_fusion_failed", "sandbox_analysis_failed", "error"]:
        print(f"\n[+] Pipeline completed with final status: {current_status}")
        break
    time.sleep(2)

print("\n[5] Inspecting generated analysis artifacts in /shared/scans/{scan_id}...")
files_list = run_cmd(f"docker exec aegis_celery_worker ls -la /shared/scans/{scan_id}")
print(files_list)
