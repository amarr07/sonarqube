# ...existing code...
import os
import subprocess
import shutil
import tempfile
import json
import time
import re
from pathlib import Path
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import uvicorn

# Optional AWS / S3
try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except Exception:
    boto3 = None

# --- Configuration ---
def load_env_file(env_path=None):
    """Load environment variables from .env file"""
    if env_path is None:
        env_path = Path.cwd() / ".env"
    else:
        env_path = Path(env_path)
    
    if env_path.exists():
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    line = line.replace('export ', '')
                    key, value = line.split('=', 1)
                    value = value.strip('"').strip("'")
                    os.environ[key] = value

load_env_file()

GITGUARDIAN_API_KEY = os.environ.get("GITGUARDIAN_API_KEY")
# S3 / MCP config
MCP_S3_BUCKET = os.environ.get("S3_BUCKET_NAME")
MCP_S3_KEY = os.environ.get("MCP_S3_KEY", "mcp.json")
AWS_REGION = os.environ.get("AWS_REGION", "ap-south-1")

# FastAPI app
app = FastAPI(title="MCP GitGuardian Scanner", version="1.0.0")

class MCPScanRequest(BaseModel):
    name: str

def extract_repo_name(repo_url):
    """Extract owner and repo name from GitHub URL"""
    repo_url = repo_url.strip().rstrip('/')
    if repo_url.startswith('git@github.com:'):
        repo_url = repo_url.replace('git@github.com:', '')
    elif 'github.com/' in repo_url:
        repo_url = repo_url.split('github.com/')[-1]
    repo_url = repo_url.replace('.git', '')
    parts = repo_url.split('/')
    if len(parts) >= 2:
        return parts[-2], parts[-1]
    return None, None

def get_mcp_json_from_s3(bucket: str, key: str) -> dict:
    """Fetch mcp.json from the given S3 bucket/key and return parsed JSON."""
    if boto3 is None:
        raise RuntimeError("boto3 is required to fetch mcp.json from S3. Install with: pip install boto3")
    s3 = boto3.client("s3", region_name=AWS_REGION)
    try:
        resp = s3.get_object(Bucket=bucket, Key=key)
        body = resp['Body'].read().decode('utf-8')
        return json.loads(body)
    except ClientError as e:
        raise RuntimeError(f"Failed to fetch {key} from bucket {bucket}: {e}")
    except BotoCoreError as e:
        raise RuntimeError(f"AWS error: {e}")
    except Exception as e:
        raise RuntimeError(f"Failed to load/parse mcp.json: {e}")

def find_server_entry(mcp_json: dict, name: str) -> Optional[dict]:
    """Find server entry by name (case-sensitive exact match)."""
    servers = mcp_json.get("servers") or []
    for s in servers:
        if s.get("name") == name:
            return s
    return None

def clone_repository(repo_url: str, target_dir: str) -> bool:
    """Clone the repository to target_dir (shallow clone)."""
    print(f"   Cloning from: {repo_url}")
    result = subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, target_dir],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"   ❌ Clone failed: {result.stderr}")
        return False
    print("   ✅ Repository cloned")
    return True

def run_ggshield_scan(path_to_scan: str) -> dict:
    """Run ggshield scan on the given path and return structured result."""
    print(f"   Running GitGuardian scanner on: {path_to_scan}")
    if not GITGUARDIAN_API_KEY:
        return {'exit_code': 500, 'error': 'GITGUARDIAN_API_KEY not configured on server'}
    
    cmd = ["ggshield", "secret", "scan", "path", path_to_scan, "--recursive", "--json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            print("   ⚠️  Scanner detected secrets!")
        else:
            print("   ✅ Scanner completed - No secrets found")
        
        # Try to parse JSON output
        scan_data = None
        if result.stdout:
            try:
                scan_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                pass
        
        return {
            'exit_code': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'scan_data': scan_data
        }
    except subprocess.TimeoutExpired:
        print("   ❌ Scanner timeout (>5 minutes)")
        return {'exit_code': 1, 'error': 'Scanner timeout'}
    except FileNotFoundError:
        return {'exit_code': 127, 'error': 'ggshield command not found. Install with: pip install ggshield'}
    except Exception as e:
        return {'exit_code': 1, 'error': str(e)}

def cleanup(path: str):
    """Clean up temporary files and directories"""
    try:
        if os.path.exists(path):
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
            print(f"   ✅ Cleaned up: {path}")
    except Exception as e:
        print(f"   ⚠️  Cleanup warning: {e}")

def save_report(repo_name: str, project_key: str, scan_result: dict, repo_url: str, output_dir=None):
    """Save scan report to JSON file"""
    print("   Generating report...")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if output_dir is None:
        report_dir = Path.cwd() / "reports"
    else:
        report_dir = Path(output_dir)
    
    report_dir.mkdir(exist_ok=True)
    
    # Extract secrets information
    secrets_found = []
    total_secrets = 0
    
    if scan_result.get('scan_data'):
        scan_data = scan_result['scan_data']
        if isinstance(scan_data, list):
            for item in scan_data:
                secrets = item.get('secrets', [])
                total_secrets += len(secrets)
                for secret in secrets:
                    secrets_found.append({
                        'type': secret.get('type'),
                        'validity': secret.get('validity'),
                        'file': item.get('filename'),
                        'line': secret.get('start_line'),
                        'match': secret.get('match', '')[0:50] + '...' if secret.get('match') else None
                    })
    
    report = {
        "metadata": {
            "repository": repo_name,
            "repo_url": repo_url,
            "project_key": project_key,
            "scan_date": datetime.now().isoformat(),
            "scanner": "GitGuardian ggshield"
        },
        "summary": {
            "scan_passed": scan_result.get('exit_code') == 0,
            "total_secrets_found": total_secrets,
            "exit_code": scan_result.get('exit_code')
        },
        "secrets": secrets_found,
        "raw_output": scan_result.get('stdout')
    }
    
    report_file = report_dir / f"ggshield-scan-{repo_name}-{timestamp}.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"   ✅ Report saved: {report_file}")
    
    latest_file = report_dir / "latest-scan-report.json"
    with open(latest_file, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"   ✅ Latest report: {latest_file}")
    
    return report_file, report

def print_summary(report_data: dict):
    """Print a summary of the scan results"""
    print("\n" + "=" * 70)
    print("GitGuardian Scan Summary")
    print("=" * 70)
    
    summary = report_data["summary"]
    metadata = report_data["metadata"]
    
    print(f"\n📦 Repository: {metadata['repository']}")
    print(f"🔗 URL: {metadata['repo_url']}")
    print(f"📅 Scan Date: {metadata['scan_date']}")
    
    print("\n🔍 Scan Results:")
    if summary['scan_passed']:
        print("   ✅ PASSED - No secrets detected")
    else:
        print(f"   ❌ FAILED - {summary['total_secrets_found']} secret(s) detected")
    
    if report_data.get('secrets'):
        print("\n🚨 Secrets Found:")
        for i, secret in enumerate(report_data['secrets'][:10], 1):  # Show first 10
            print(f"\n   [{i}] {secret.get('type', 'Unknown')}")
            print(f"       File: {secret.get('file')}")
            print(f"       Line: {secret.get('line')}")
            print(f"       Validity: {secret.get('validity', 'Unknown')}")
        
        if len(report_data['secrets']) > 10:
            print(f"\n   ... and {len(report_data['secrets']) - 10} more secrets")
    
    print("\n" + "=" * 70)

@app.get("/")
async def index():
    return {
        "service": "MCP GitGuardian Scanner",
        "version": "1.0.0",
        "notes": "POST /scan_mcp with JSON {\"name\": \"<mcp-name>\"} to run a scan on the repo defined in mcp.json in S3."
    }

@app.get("/health")
async def health():
    ok = bool(GITGUARDIAN_API_KEY and MCP_S3_BUCKET)
    return {"status": "healthy" if ok else "unhealthy", "gitguardian_configured": bool(GITGUARDIAN_API_KEY), "mcp_s3_bucket": bool(MCP_S3_BUCKET)}

@app.post("/scan_mcp")
async def scan_mcp(req: MCPScanRequest):
    """
    Body: { "name": "<mcp-server-name>" }
    Fetches mcp.json from S3, finds the server by name, clones the associated repo,
    runs ggshield scan on it, returns results.
    """
    if not GITGUARDIAN_API_KEY:
        raise HTTPException(status_code=500, detail="GITGUARDIAN_API_KEY not configured on server")
    if not MCP_S3_BUCKET:
        raise HTTPException(status_code=500, detail="MCP_S3_BUCKET not configured on server")

    print("\n" + "=" * 70)
    print("🚀 Automated GitGuardian MCP Scanner")
    print("=" * 70)
    print(f"\n✅ MCP Server Name: {req.name}")
    print(f"✅ S3 Bucket: {MCP_S3_BUCKET}")
    print(f"✅ S3 Key: {MCP_S3_KEY}")

    temp_root = tempfile.mkdtemp(prefix="mcp_ggshield_scan_")
    clone_dir = os.path.join(temp_root, "repo")
    
    try:
        # Step 1: Fetch mcp.json from S3
        print(f"\n[1/5] 🔧 Fetching MCP Configuration from S3")
        try:
            mcp_json = get_mcp_json_from_s3(MCP_S3_BUCKET, MCP_S3_KEY)
            print("   ✅ Successfully fetched mcp.json")
        except Exception as e:
            print(f"   ❌ Failed to fetch mcp.json: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to fetch mcp.json: {e}")

        # Step 2: Find server entry
        print(f"\n[2/5] 🔍 Searching for MCP Server")
        server = find_server_entry(mcp_json, req.name)
        if not server:
            print(f"   ❌ Server '{req.name}' not found")
            raise HTTPException(status_code=404, detail=f"MCP server '{req.name}' not found in {MCP_S3_KEY}")

        repo_info = server.get("repository") or {}
        repo_url = repo_info.get("url")
        if not repo_url:
            print(f"   ❌ No repository URL defined")
            raise HTTPException(status_code=400, detail=f"No repository URL defined for MCP server '{req.name}'")
        
        print(f"   ✅ Found server: {server.get('name')}")
        print(f"   📦 Repository: {repo_url}")
        
        owner, repo = extract_repo_name(repo_url)
        repo_name = f"{owner}_{repo}" if owner and repo else req.name
        project_key = f"mcp_{repo_name}"

        # Step 3: Clone repository
        print(f"\n[3/5] 📥 Cloning Repository")
        if not clone_repository(repo_url, clone_dir):
            cleanup(temp_root)
            raise HTTPException(status_code=500, detail=f"Failed to clone repository '{repo_url}'")

        # Step 4: Run GitGuardian scan
        print(f"\n[4/5] 🔍 Running GitGuardian Security Scan")
        scan_result = run_ggshield_scan(clone_dir)
        
        if 'error' in scan_result:
            print(f"   ❌ Scan error: {scan_result['error']}")
            cleanup(temp_root)
            raise HTTPException(status_code=500, detail=f"Scan failed: {scan_result['error']}")

        # Step 5: Generate report
        print(f"\n[5/5] 📄 Generating Report")
        report_file, report_data = save_report(repo_name, project_key, scan_result, repo_url)
        
        # Print summary
        print_summary(report_data)
        
        print("\n" + "=" * 70)
        if scan_result.get('exit_code') == 0:
            print("✅ Scan Complete - No Secrets Found!")
        else:
            print("⚠️  Scan Complete - Secrets Detected!")
        print("=" * 70)
        print(f"\n📁 Report saved to: {report_file}")
        print()

        # Prepare API response
        response = {
            "success": scan_result.get("exit_code") == 0,
            "mcp_server": server.get("name"),
            "repo_url": repo_url,
            "report_file": str(report_file),
            "summary": report_data.get("summary"),
            "metadata": report_data.get("metadata")
        }
        
        # Include secrets if found (first 5 for API response)
        if report_data.get('secrets'):
            response['secrets_preview'] = report_data['secrets'][:5]
            response['total_secrets'] = len(report_data['secrets'])

        status_code = 200 if scan_result.get("exit_code") == 0 else 400
        return JSONResponse(content=response, status_code=status_code)

    except HTTPException:
        raise
    finally:
        print("\n🧹 Cleaning up temporary files...")
        cleanup(temp_root)
        print("   ✅ Cleanup complete\n")

if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("🚀 MCP GitGuardian Scanner API")
    print("=" * 70)
    
    if not GITGUARDIAN_API_KEY:
        print("\n⚠️  WARNING: GITGUARDIAN_API_KEY is not set!")
        print("Please set it in your .env file or environment variables.")
    else:
        print("\n✅ GitGuardian API Key: Configured")
    
    if not MCP_S3_BUCKET:
        print("⚠️  WARNING: S3_BUCKET_NAME not set!")
        print("Please set it in your .env file or environment variables.")
    else:
        print(f"✅ S3 Bucket: {MCP_S3_BUCKET}")
        print(f"✅ S3 Key: {MCP_S3_KEY}")
    
    print("\n" + "=" * 70)
    print("Starting API on http://0.0.0.0:8001")
    print("=" * 70 + "\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="info")