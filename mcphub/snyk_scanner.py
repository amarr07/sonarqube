"""
Bandit Security Scanner - Python Code Security Analysis
========================================================
Scans GitHub repositories for security vulnerabilities using Bandit.
Fetches repository information from S3 bucket (mcp.json) and performs security analysis.

Requirements:
- boto3 (AWS S3 access)
- bandit (Security scanning)
- GitPython (Git operations)
- python-dotenv (Environment variables)

Environment Variables (.env):
- AWS_ACCESS_KEY_ID: AWS access key
- AWS_SECRET_ACCESS_KEY: AWS secret key
- AWS_REGION: AWS region (default: us-east-1)
- S3_BUCKET_NAME: S3 bucket containing mcp.json
- S3_MCP_JSON_KEY: Path to mcp.json in S3 bucket
- GITHUB_TOKEN: (Optional) For private repositories
"""

import os
import sys
import json
import shutil
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime

# Third-party imports
try:
    import boto3
    from git import Repo
    from dotenv import load_dotenv
except ImportError as e:
    print(f"❌ Missing required dependency: {e}")
    print("Install dependencies: pip install boto3 bandit GitPython python-dotenv")
    sys.exit(1)

# Load environment variables
load_dotenv()

# --- Configuration ---
AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
S3_BUCKET_NAME = os.environ.get("S3_BUCKET_NAME")
S3_MCP_JSON_KEY = os.environ.get("S3_MCP_JSON_KEY", "mcp.json")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")


class BanditScanner:
    """Handles Python security scanning using Bandit"""
    
    def __init__(self):
        # Check if bandit is installed
        try:
            result = subprocess.run(
                ["bandit", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                print(f"✓ Bandit installed: {result.stdout.strip()}")
            else:
                raise Exception("Bandit not installed")
        except FileNotFoundError:
            raise Exception("Bandit not found. Install with: pip install bandit")
        except Exception as e:
            raise Exception(f"Bandit check failed: {e}")
    
    def scan_repository(self, repo_path: str) -> Dict:
        """
        Scan Python repository for security issues using Bandit
        
        Args:
            repo_path: Path to the cloned repository
            
        Returns:
            Dictionary with scan results
        """
        if not os.path.exists(repo_path):
            return {"error": "Repository path not found", "issues": []}
        
        try:
            # Create temp file for JSON output
            output_file = os.path.join(tempfile.gettempdir(), f"bandit_report_{datetime.now().timestamp()}.json")
            
            print(f"\n[Bandit] Scanning Python code for security issues...")
            
            # Run bandit scan
            result = subprocess.run(
                [
                    "bandit",
                    "-r",  # Recursive
                    repo_path,
                    "-f", "json",  # JSON format
                    "-o", output_file,  # Output file
                    "-ll"  # Low confidence and low severity minimum
                ],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Bandit exit codes: 0 = no issues, 1 = issues found, other = error
            # Read the JSON output
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    bandit_results = json.load(f)
                
                # Clean up temp file
                os.remove(output_file)
                
                return self._parse_bandit_results(bandit_results)
            else:
                return {
                    "error": "Bandit did not generate output file",
                    "details": result.stderr,
                    "issues": []
                }
                
        except subprocess.TimeoutExpired:
            return {"error": "Bandit scan timed out (>2 minutes)", "issues": []}
        except Exception as e:
            return {"error": str(e), "issues": []}
    
    def _parse_bandit_results(self, result: Dict) -> Dict:
        """Parse Bandit JSON results into readable format"""
        issues = result.get("results", [])
        metrics = result.get("metrics", {})
        
        severity_counts = {
            "high": 0,
            "medium": 0,
            "low": 0
        }
        
        confidence_map = {
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low"
        }
        
        detailed_issues = []
        
        for issue in issues:
            severity = issue.get("issue_severity", "UNDEFINED").upper()
            confidence = issue.get("issue_confidence", "UNDEFINED").upper()
            
            # Map Bandit severity to our format
            sev_key = confidence_map.get(severity, "low")
            if sev_key in severity_counts:
                severity_counts[sev_key] += 1
            
            detailed_issues.append({
                "title": issue.get("issue_text", "Unknown security issue"),
                "severity": sev_key,
                "confidence": confidence_map.get(confidence, "low"),
                "file": issue.get("filename", "Unknown"),
                "line_number": issue.get("line_number", 0),
                "code": issue.get("code", ""),
                "test_id": issue.get("test_id", ""),
                "test_name": issue.get("test_name", ""),
                "cwe": issue.get("issue_cwe", {}).get("id", "N/A")
            })
        
        # Sort by severity
        severity_order = {"high": 0, "medium": 1, "low": 2}
        detailed_issues.sort(key=lambda x: severity_order.get(x["severity"], 3))
        
        total_lines = sum(metrics.get("_totals", {}).get("loc", 0) for metrics in [metrics])
        
        return {
            "ok": len(issues) == 0,
            "total_issues": len(issues),
            "severity_counts": severity_counts,
            "issues": detailed_issues,
            "total_lines_scanned": total_lines,
            "scanner": "Bandit"
        }


class S3Handler:
    """Handles S3 operations for fetching mcp.json"""
    
    def __init__(self, access_key: str, secret_key: str, region: str):
        self.s3_client = boto3.client(
            's3',
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )
    
    def fetch_mcp_json(self, bucket: str, key: str) -> Optional[List[Dict]]:
        """Fetch and parse mcp.json from S3"""
        try:
            print(f"\n[S3] Fetching {key} from bucket: {bucket}")
            response = self.s3_client.get_object(Bucket=bucket, Key=key)
            content = response['Body'].read().decode('utf-8')
            data = json.loads(content)
            
            # Handle different formats
            if isinstance(data, list):
                # Already an array of MCP servers
                return data
            elif isinstance(data, dict):
                # Check if it's a nested structure with multiple keys
                if "mcphub-servers" in data or "servers" in data:
                    # Combine all arrays into one list
                    all_servers = []
                    if "mcphub-servers" in data and isinstance(data["mcphub-servers"], list):
                        all_servers.extend(data["mcphub-servers"])
                    if "servers" in data and isinstance(data["servers"], list):
                        all_servers.extend(data["servers"])
                    
                    if all_servers:
                        print(f"✓ Found nested structure with {len(all_servers)} total server(s)")
                        return all_servers
                    else:
                        print("❌ No servers found in mcphub-servers or servers arrays")
                        return None
                else:
                    # Single MCP server object, wrap it in a list
                    return [data]
            else:
                print("❌ Invalid mcp.json format - expected array or object")
                return None
                
        except Exception as e:
            print(f"❌ Failed to fetch from S3: {e}")
            return None
    
    def find_mcp_by_name(self, mcp_servers: List[Dict], name: str) -> Optional[Dict]:
        """
        Find an MCP server by name from the list
        
        Args:
            mcp_servers: List of MCP server configurations
            name: Name of the MCP server to find
            
        Returns:
            MCP server configuration dict or None if not found
        """
        for mcp in mcp_servers:
            if mcp.get("name", "").lower() == name.lower():
                return mcp
        return None
    
    def list_available_mcps(self, mcp_servers: List[Dict]) -> None:
        """Print list of available MCP servers"""
        print("\n📋 Available MCP Servers:")
        print("-" * 70)
        for idx, mcp in enumerate(mcp_servers, 1):
            name = mcp.get("name", "Unknown")
            description = mcp.get("description", "No description")
            repo_url = mcp.get("repository", {}).get("url", "No repository")
            lang = mcp.get("lang", "Unknown")
            
            print(f"\n{idx}. {name}")
            print(f"   Language: {lang}")
            print(f"   Description: {description}")
            print(f"   Repository: {repo_url}")
        print("-" * 70)


class GitHandler:
    """Handles Git repository operations"""
    
    @staticmethod
    def clone_repository(repo_url: str, target_dir: str, token: Optional[str] = None) -> bool:
        """
        Clone a Git repository
        
        Args:
            repo_url: GitHub repository URL
            target_dir: Directory to clone into
            token: Optional GitHub token for private repos
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Add token to URL if provided (for private repos)
            if token and "github.com" in repo_url:
                repo_url = repo_url.replace("https://", f"https://{token}@")
            
            print(f"\n[Git] Cloning repository: {repo_url}")
            Repo.clone_from(repo_url, target_dir, depth=1)  # Shallow clone
            print(f"✓ Repository cloned to: {target_dir}")
            return True
        except Exception as e:
            print(f"❌ Failed to clone repository: {e}")
            return False


def print_scan_report(scan_results: Dict, repo_name: str):
    """Print formatted scan report"""
    print("\n" + "="*70)
    print(f"  BANDIT SECURITY SCAN REPORT - {repo_name}")
    print("="*70)
    
    if "error" in scan_results:
        print(f"\n❌ Scan Error: {scan_results['error']}")
        if "details" in scan_results:
            print(f"Details: {scan_results['details']}")
        return
    
    print(f"\n� Scanner: {scan_results.get('scanner', 'Bandit')}")
    print(f"📊 Lines of Code Scanned: {scan_results.get('total_lines_scanned', 0)}")
    print(f"� Total Issues Found: {scan_results['total_issues']}")
    
    severity = scan_results['severity_counts']
    print(f"\n� Severity Breakdown:")
    print(f"   High:     {severity['high']}")
    print(f"   Medium:   {severity['medium']}")
    print(f"   Low:      {severity['low']}")
    
    if scan_results['total_issues'] > 0:
        print(f"\n📋 Issue Details:")
        for idx, issue in enumerate(scan_results['issues'][:15], 1):  # Show first 15
            print(f"\n  {idx}. [{issue['severity'].upper()}] {issue['title']}")
            print(f"     File: {issue['file']}")
            print(f"     Line: {issue['line_number']}")
            print(f"     Confidence: {issue['confidence'].upper()}")
            print(f"     Test: {issue['test_id']} - {issue['test_name']}")
            if issue.get('cwe') and issue['cwe'] != 'N/A':
                print(f"     CWE: {issue['cwe']}")
        
        if len(scan_results['issues']) > 15:
            print(f"\n  ... and {len(scan_results['issues']) - 15} more issues")
    
    # Final verdict
    print("\n" + "="*70)
    if scan_results['ok']:
        print("✅ SCAN PASSED: No security issues found!")
    else:
        print("❌ SCAN FAILED: Security issues detected!")
        print("   Review issues above and remediate before deployment.")
    print("="*70 + "\n")


def validate_environment() -> bool:
    """Validate all required environment variables are set"""
    required_vars = {
        "AWS_ACCESS_KEY_ID": AWS_ACCESS_KEY,
        "AWS_SECRET_ACCESS_KEY": AWS_SECRET_KEY,
        "S3_BUCKET_NAME": S3_BUCKET_NAME
    }
    
    missing = [var for var, value in required_vars.items() if not value]
    
    if missing:
        print("❌ Missing required environment variables:")
        for var in missing:
            print(f"   - {var}")
        print("\nPlease set these in your .env file.")
        return False
    
    print("✓ All required environment variables are set")
    return True


def get_user_choice(mcp_servers: List[Dict]) -> Optional[Dict]:
    """
    Get user's choice of MCP server to scan
    
    Args:
        mcp_servers: List of available MCP servers
        
    Returns:
        Selected MCP server configuration or None
    """
    while True:
        print("\n" + "="*70)
        print("  SELECT MCP SERVER TO SCAN")
        print("="*70)
        print("\nEnter the name of the MCP server you want to scan.")
        print("Type 'list' to see all available servers.")
        print("Type 'quit' to exit.")
        print("-" * 70)
        
        user_input = input("\n👉 MCP Server Name: ").strip()
        
        if user_input.lower() == 'quit':
            print("Exiting...")
            return None
        
        if user_input.lower() == 'list':
            s3_handler = S3Handler(AWS_ACCESS_KEY, AWS_SECRET_KEY, AWS_REGION)
            s3_handler.list_available_mcps(mcp_servers)
            continue
        
        if not user_input:
            print("❌ Please enter a valid MCP server name.")
            continue
        
        # Search for the MCP server
        s3_handler = S3Handler(AWS_ACCESS_KEY, AWS_SECRET_KEY, AWS_REGION)
        selected_mcp = s3_handler.find_mcp_by_name(mcp_servers, user_input)
        
        if selected_mcp:
            print(f"\n✓ Found MCP server: {selected_mcp.get('name')}")
            return selected_mcp
        else:
            print(f"\n❌ MCP server '{user_input}' not found.")
            print("   Type 'list' to see all available servers.")
            continue


def main():
    """Main execution flow"""
    print("="*70)
    print("  BANDIT SECURITY SCANNER - Python Code Analysis")
    print("="*70)
    
    # 1. Validate environment
    if not validate_environment():
        sys.exit(1)
    
    # 2. Initialize handlers
    s3_handler = S3Handler(AWS_ACCESS_KEY, AWS_SECRET_KEY, AWS_REGION)
    
    # 3. Initialize Bandit scanner
    try:
        bandit_scanner = BanditScanner()
    except Exception as e:
        print(f"❌ Failed to initialize Bandit: {e}")
        sys.exit(1)
    
    # 4. Fetch mcp.json from S3 (returns list of MCP servers)
    mcp_servers = s3_handler.fetch_mcp_json(S3_BUCKET_NAME, S3_MCP_JSON_KEY)
    if not mcp_servers:
        print("❌ Failed to fetch mcp.json from S3 or file is empty")
        sys.exit(1)
    
    print(f"✓ Found {len(mcp_servers)} MCP server(s) in configuration")
    
    # 5. Let user select which MCP server to scan
    selected_mcp = get_user_choice(mcp_servers)
    if not selected_mcp:
        sys.exit(0)  # User chose to quit
    
    # 6. Extract repository URL from selected MCP
    repo_url = selected_mcp.get("repository", {}).get("url")
    repo_name = selected_mcp.get("name", "unknown")
    
    if not repo_url:
        print(f"❌ No repository URL found for MCP server '{repo_name}'")
        sys.exit(1)
    
    print(f"\n✓ Repository URL: {repo_url}")
    print(f"✓ Project Name: {repo_name}")
    print(f"✓ Language: {selected_mcp.get('lang', 'Unknown')}")
    print(f"✓ Description: {selected_mcp.get('description', 'No description')}")
    
    # 7. Clone repository to temp directory
    temp_dir = tempfile.mkdtemp(prefix=f"bandit_scan_{repo_name}_")
    
    try:
        if not GitHandler.clone_repository(repo_url, temp_dir, GITHUB_TOKEN):
            sys.exit(1)
        
        # 8. Run Bandit security scan
        scan_results = bandit_scanner.scan_repository(temp_dir)
        
        # 9. Display results
        print_scan_report(scan_results, repo_name)
        
        # 10. Exit with appropriate code
        if scan_results.get('ok', False):
            sys.exit(0)
        else:
            sys.exit(1)
            
    finally:
        # 11. Cleanup
        print(f"\n[Cleanup] Removing temporary directory: {temp_dir}")
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
