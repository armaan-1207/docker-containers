import urllib.request
import urllib.parse
import json
import ssl
import base64
import time
import subprocess
import sys
import os
import uuid
import argparse

parser = argparse.ArgumentParser(description="AEGIS E2E Integration Test Runner")
parser.add_argument("--host", default=os.environ.get("AEGIS_HOST", "https://localhost"), help="Target API host")
parser.add_argument("--email", default=os.environ.get("TEST_EMAIL", "analyst@test.com"), help="Test account email")
parser.add_argument("--password", help="Test account password (will prompt if omitted)")
parser.add_argument("--ca-bundle", default=os.environ.get("SSL_CERT_FILE"), help="Path to CA bundle for TLS verification")
parser.add_argument("--insecure", action="store_true", default=False, help="Disable TLS certificate verification (only auto-enabled for localhost/127.0.0.1 targets)")
parser.add_argument("--url", default="https://example.com/", help="Target URL to scan")
args = parser.parse_known_args()[0]

password = args.password or os.environ.get("TEST_PASSWORD")
if not password:
    import getpass
    password = getpass.getpass("Enter test account password: ")
    if not password:
        print("FATAL: Password is required.", file=sys.stderr)
        sys.exit(1)
args.password = password

ctx = ssl.create_default_context()
if args.ca_bundle and os.path.exists(args.ca_bundle):
    ctx.load_verify_locations(args.ca_bundle)
elif args.insecure or "localhost" in args.host or "127.0.0.1" in args.host:
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    print("[WARNING] TLS verification disabled (--insecure or localhost target). Do not use across untrusted networks.")

# 1x1 transparent PNG base64
valid_png = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==')
screenshot_b64 = base64.b64encode(valid_png).decode()

def run_cmd(cmd_args):
    return subprocess.check_output(cmd_args).decode().strip()

print("=======================================================================")
print("                      AEGIS PIPELINE SCANNER                           ")
print("=======================================================================")

# 1. Automatically register user if missing (returns 202 Accepted)
print(f"\n[1] Ensuring user account ({args.email}) exists on {args.host}...")
reg_payload = json.dumps({'email': args.email, 'password': args.password}).encode()
reg_req = urllib.request.Request(f'{args.host.rstrip("/")}/api/auth/register', data=reg_payload, headers={'Content-Type': 'application/json'}, method='POST')
try:
    urllib.request.urlopen(reg_req, context=ctx)  # nosec B310
    print("    -> User ensured/created.")
except Exception:
    print("    -> User already exists.")

# 2. Login to get JWT Token
print("\n[2] Authenticating with Nginx ingress (POST /api/auth/login)...")
login_data = f'username={urllib.parse.quote(args.email)}&password={urllib.parse.quote(args.password)}'.encode()
req = urllib.request.Request(f'{args.host.rstrip("/")}/api/auth/login', data=login_data, headers={'Content-Type': 'application/x-www-form-urlencoded'}, method='POST')
try:
    auth_resp = urllib.request.urlopen(req, context=ctx)  # nosec B310
    token = json.loads(auth_resp.read().decode())['access_token']
    print("    -> SUCCESS: JWT access token acquired.")
except Exception as e:
    print(f"    -> FATAL: Authentication failed: {e}")
    sys.exit(1)

# 3. Submit Stage 2 Scan
target_url = args.url
print(f"\n[3] Submitting Stage 2 scan payload for: {target_url}...")
html_payload = f"<html><head><title>Scan Target</title></head><body><h1>Scan Test for {target_url}</h1></body></html>"
stage2_payload = json.dumps({
    'url': target_url,
    'screenshot_base64': screenshot_b64,
    'html': html_payload
}).encode()

req_scan = urllib.request.Request(f'{args.host.rstrip("/")}/api/scans/stage2', data=stage2_payload, headers={
    'Authorization': f'Bearer {token}',
    'Content-Type': 'application/json'
}, method='POST')

try:
    scan_resp = urllib.request.urlopen(req_scan, context=ctx)  # nosec B310
    scan_res = json.loads(scan_resp.read().decode())
    scan_id = str(uuid.UUID(scan_res['scan_id']))  # Validate server UUID
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
    status_query = [
        "docker", "exec", "-u", "postgres", "aegis_postgres",
        "psql", "-d", "aegis_db", "-t",
        "-c", f"SELECT status, risk_score, severity FROM scans WHERE id = '{scan_id}';"
    ]
    row = run_cmd(status_query).strip()
    parts = [p.strip() for p in row.split('|')] if '|' in row else [row]
    current_status = parts[0] if parts else "unknown"
    score = parts[1] if len(parts) > 1 else ""
    sev = parts[2] if len(parts) > 2 else ""
    
    elapsed = int(time.time() - start_time)
    print(f"    [{elapsed:02d}s] Status: {current_status:<25} | score: {score:<6} | severity: {sev}")
    
    if current_status == "risk_fusion_done":
        print(f"\n[+] Pipeline completed successfully with final status: {current_status}")
        break
    elif current_status.endswith("_failed") or current_status.startswith("failed") or current_status in ["error", "risk_fusion_failed", "sandbox_analysis_failed"]:
        print(f"\n[-] Pipeline aborted with terminal failure status: {current_status}")
        break
    time.sleep(2)

print("\n[5] Inspecting generated analysis artifacts in /shared/scans/{scan_id}...")
files_list = run_cmd(["docker", "exec", "aegis_celery_worker", "ls", "-la", f"/shared/scans/{scan_id}"])
print(files_list)
