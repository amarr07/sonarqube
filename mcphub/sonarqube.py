import os
import subprocess
import tempfile
import shutil
import json
import time
import re
from pathlib import Path
from datetime import datetime
import requests

def load_env_file(env_path=None):
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

def extract_repo_name(repo_url):
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

def generate_project_key(owner, repo, organization):
    safe_owner = re.sub(r'[^a-zA-Z0-9_\-.]', '_', owner)
    safe_repo = re.sub(r'[^a-zA-Z0-9_\-.]', '_', repo)
    return f"{organization}_{safe_owner}_{safe_repo}"

def create_sonarcloud_project(project_key, project_name, sonar_host, sonar_token, sonar_org):
    print(f"   Creating project: {project_key}")
    url = f"{sonar_host}/api/projects/create"
    params = {
        "organization": sonar_org,
        "project": project_key,
        "name": project_name
    }
    headers = {"Authorization": f"Bearer {sonar_token}"}
    try:
        response = requests.post(url, params=params, headers=headers, timeout=30)
        if response.status_code == 200:
            print("   ✅ Project created successfully")
            return True
        elif response.status_code == 400:
            error_msg = response.text.lower()
            if "already exists" in error_msg or "already" in error_msg:
                print("   ✅ Project already exists (will reuse)")
                return True
            else:
                print(f"   ⚠️  API Error: {response.text}")
                return False
        else:
            print(f"   ⚠️  Failed to create project: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"   ⚠️  Network error: {str(e)}")
        return False

def clone_repository(repo_url, target_dir):
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

def run_sonar_scanner(repo_path, project_key, sonar_host, sonar_token, sonar_org):
    print(f"   Running scanner on: {repo_path}")
    print(f"   Project key: {project_key}")
    original_dir = os.getcwd()
    os.chdir(repo_path)
    try:
        result = subprocess.run([
            "sonar-scanner",
            f"-Dsonar.projectKey={project_key}",
            f"-Dsonar.organization={sonar_org}",
            "-Dsonar.sources=.",
            "-Dsonar.sourceEncoding=UTF-8",
            f"-Dsonar.host.url={sonar_host}",
            f"-Dsonar.login={sonar_token}"
        ], capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            print("   ❌ Scanner failed!")
            print("\n--- Scanner Output ---")
            print(result.stdout)
            if result.stderr:
                print("\n--- Scanner Errors ---")
                print(result.stderr)
            return False
        print("   ✅ Scanner completed successfully")
        for line in result.stdout.split('\n'):
            if 'ceTaskId' in line or 'task?' in line:
                print(f"   {line.strip()}")
        return True
    except subprocess.TimeoutExpired:
        print("   ❌ Scanner timeout (>5 minutes)")
        return False
    finally:
        os.chdir(original_dir)

def wait_for_analysis_completion(project_key, sonar_host, sonar_token, max_wait=60):
    print("   Waiting for SonarCloud to process results...")
    url = f"{sonar_host}/api/ce/component"
    params = {"component": project_key}
    headers = {"Authorization": f"Bearer {sonar_token}"}
    start_time = time.time()
    while time.time() - start_time < max_wait:
        try:
            response = requests.get(url, params=params, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get("queue"):
                    print("   ⏳ Still in queue...", end='\r')
                    time.sleep(3)
                    continue
                current = data.get("current")
                if current:
                    status = current.get("status")
                    if status == "SUCCESS":
                        print("   ✅ Analysis processing complete     ")
                        return True
                    elif status in ["PENDING", "IN_PROGRESS"]:
                        print(f"   ⏳ Status: {status}...", end='\r')
                        time.sleep(3)
                        continue
                    else:
                        print(f"   ⚠️  Status: {status}")
                        return False
                else:
                    print("   ✅ Analysis appears ready")
                    return True
            time.sleep(3)
        except Exception as e:
            print(f"   ⚠️  Error checking status: {str(e)}")
            time.sleep(3)
    print("   ⚠️  Timeout waiting for analysis")
    return True

def fetch_issues(project_key, sonar_host, sonar_token):
    print("   Fetching issues...")
    url = f"{sonar_host}/api/issues/search"
    headers = {"Authorization": f"Bearer {sonar_token}"}
    all_issues = []
    page = 1
    page_size = 500
    while True:
        params = {"componentKeys": project_key, "ps": page_size, "p": page}
        try:
            response = requests.get(url, params=params, headers=headers, timeout=30)
            if response.status_code != 200:
                print(f"   ⚠️  Failed to fetch issues: {response.status_code}")
                break
            data = response.json()
            issues = data.get("issues", [])
            all_issues.extend(issues)
            total = data.get("total", 0)
            if len(all_issues) >= total or len(issues) < page_size:
                break
            page += 1
        except Exception as e:
            print(f"   ⚠️  Error fetching issues: {str(e)}")
            break
    print(f"   ✅ Found {len(all_issues)} issues")
    return all_issues

def fetch_hotspots(project_key, sonar_host, sonar_token):
    print("   Fetching security hotspots...")
    url = f"{sonar_host}/api/hotspots/search"
    headers = {"Authorization": f"Bearer {sonar_token}"}
    all_hotspots = []
    page = 1
    page_size = 500
    while True:
        params = {"projectKey": project_key, "ps": page_size, "p": page}
        try:
            response = requests.get(url, params=params, headers=headers, timeout=30)
            if response.status_code != 200:
                print(f"   ⚠️  Failed to fetch hotspots: {response.status_code}")
                break
            data = response.json()
            hotspots = data.get("hotspots", [])
            all_hotspots.extend(hotspots)
            paging = data.get("paging", {})
            total = paging.get("total", 0)
            if len(all_hotspots) >= total or len(hotspots) < page_size:
                break
            page += 1
        except Exception as e:
            print(f"   ⚠️  Error fetching hotspots: {str(e)}")
            break
    print(f"   ✅ Found {len(all_hotspots)} security hotspots")
    return all_hotspots

def fetch_measures(project_key, sonar_host, sonar_token):
    print("   Fetching code metrics...")
    url = f"{sonar_host}/api/measures/component"
    headers = {"Authorization": f"Bearer {sonar_token}"}
    metric_keys = [
        "ncloc", "coverage", "bugs", "vulnerabilities", "code_smells",
        "security_hotspots", "sqale_rating", "reliability_rating",
        "security_rating", "duplicated_lines_density", "complexity"
    ]
    params = {"component": project_key, "metricKeys": ",".join(metric_keys)}
    try:
        response = requests.get(url, params=params, headers=headers, timeout=30)
        if response.status_code != 200:
            print(f"   ⚠️  Failed to fetch metrics: {response.status_code}")
            return {}
        data = response.json()
        component = data.get("component", {})
        measures = component.get("measures", [])
        metrics = {}
        for measure in measures:
            metric = measure.get("metric")
            value = measure.get("value")
            metrics[metric] = value
        print(f"   ✅ Retrieved {len(metrics)} metrics")
        return metrics
    except Exception as e:
        print(f"   ⚠️  Error fetching metrics: {str(e)}")
        return {}

def format_issues_by_severity(issues):
    by_severity = {"BLOCKER": [], "CRITICAL": [], "MAJOR": [], "MINOR": [], "INFO": []}
    for issue in issues:
        severity = issue.get("severity", "INFO")
        by_severity[severity].append({
            "type": issue.get("type"),
            "rule": issue.get("rule"),
            "message": issue.get("message"),
            "file": issue.get("component", "").split(":")[-1],
            "line": issue.get("line"),
            "status": issue.get("status")
        })
    return by_severity

def save_report(repo_name, project_key, issues, hotspots, metrics, sonar_host, output_dir=None):
    print("   Generating report...")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if output_dir is None:
        report_dir = Path.cwd() / "reports"
    else:
        report_dir = Path(output_dir)
    
    report_dir.mkdir(exist_ok=True)
    issues_by_severity = format_issues_by_severity(issues)
    bugs = [i for i in issues if i.get("type") == "BUG"]
    vulnerabilities = [i for i in issues if i.get("type") == "VULNERABILITY"]
    code_smells = [i for i in issues if i.get("type") == "CODE_SMELL"]
    report = {
        "metadata": {
            "repository": repo_name,
            "project_key": project_key,
            "analysis_date": datetime.now().isoformat(),
            "sonarcloud_url": f"{sonar_host}/dashboard?id={project_key}"
        },
        "summary": {
            "total_issues": len(issues),
            "bugs": len(bugs),
            "vulnerabilities": len(vulnerabilities),
            "code_smells": len(code_smells),
            "security_hotspots": len(hotspots)
        },
        "metrics": metrics,
        "issues": {
            "by_severity": {
                "blocker": len(issues_by_severity["BLOCKER"]),
                "critical": len(issues_by_severity["CRITICAL"]),
                "major": len(issues_by_severity["MAJOR"]),
                "minor": len(issues_by_severity["MINOR"]),
                "info": len(issues_by_severity["INFO"])
            },
            "details": issues_by_severity
        },
        "security_hotspots": [
            {
                "message": h.get("message"),
                "file": h.get("component", "").split(":")[-1],
                "line": h.get("line"),
                "status": h.get("status"),
                "category": h.get("securityCategory")
            }
            for h in hotspots
        ]
    }
    report_file = report_dir / f"full-analysis-{repo_name}-{timestamp}.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"   ✅ Report saved: {report_file}")
    latest_file = report_dir / "analysis-report.json"
    with open(latest_file, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"   ✅ Latest report: {latest_file}")
    return report_file, report

def print_summary(report_data):
    print("\n" + "=" * 70)
    print("Analysis Summary")
    print("=" * 70)
    summary = report_data["summary"]
    metrics = report_data["metrics"]
    print("\n📊 Issue Counts:")
    print(f"   Total Issues:        {summary['total_issues']}")
    print(f"   🐛 Bugs:             {summary['bugs']}")
    print(f"   🔒 Vulnerabilities:  {summary['vulnerabilities']}")
    print(f"   💨 Code Smells:      {summary['code_smells']}")
    print(f"   🔐 Security Hotspots: {summary['security_hotspots']}")
    print("\n📏 Code Metrics:")
    if "ncloc" in metrics:
        print(f"   Lines of Code:       {metrics['ncloc']}")
    if "complexity" in metrics:
        print(f"   Complexity:          {metrics['complexity']}")
    if "duplicated_lines_density" in metrics:
        print(f"   Duplication:         {metrics['duplicated_lines_density']}%")
    if "coverage" in metrics:
        print(f"   Coverage:            {metrics['coverage']}%")
    print("\n🎯 Quality Ratings:")
    ratings = {"A": "⭐⭐⭐⭐⭐", "B": "⭐⭐⭐⭐", "C": "⭐⭐⭐", "D": "⭐⭐", "E": "⭐"}
    if "reliability_rating" in metrics:
        rating = chr(64 + int(float(metrics["reliability_rating"])))
        print(f"   Reliability:         {rating} {ratings.get(rating, '')}")
    if "security_rating" in metrics:
        rating = chr(64 + int(float(metrics["security_rating"])))
        print(f"   Security:            {rating} {ratings.get(rating, '')}")
    if "sqale_rating" in metrics:
        rating = chr(64 + int(float(metrics["sqale_rating"])))
        print(f"   Maintainability:     {rating} {ratings.get(rating, '')}")

def run_analysis(repo_url, env_path=None):
    load_env_file(env_path)
    
    SONAR_HOST = "https://sonarcloud.io"
    SONAR_TOKEN = os.environ.get("SONAR_TOKEN", "")
    SONAR_ORGANIZATION = os.environ.get("SONAR_ORGANIZATION", "")
    
    if not SONAR_TOKEN:
        raise ValueError("❌ Error: SONAR_TOKEN not found in .env file")
    
    if not SONAR_ORGANIZATION:
        raise ValueError("❌ Error: SONAR_ORGANIZATION not found in .env file")
    
    print("\n" + "=" * 70)
    print("🚀 Automated SonarCloud Analyzer")
    print("=" * 70)
    print(f"\n✅ Organization: {SONAR_ORGANIZATION}")
    print("✅ Token: Configured")
    
    print(f"\n📦 Repository: {repo_url}")
    owner, repo = extract_repo_name(repo_url)
    if not owner or not repo:
        raise ValueError("❌ Error: Could not parse repository URL")
    
    repo_name = f"{owner}_{repo}"
    project_key = generate_project_key(owner, repo, SONAR_ORGANIZATION)
    print(f"   Owner: {owner}")
    print(f"   Repo: {repo}")
    print(f"   Project Key: {project_key}")
    
    tmp_dir = tempfile.mkdtemp(prefix="sonarcloud_auto_")
    repo_path = os.path.join(tmp_dir, "repo")
    
    try:
        print(f"\n[1/5] 🔧 Creating SonarCloud Project")
        if not create_sonarcloud_project(project_key, f"{owner}/{repo}", SONAR_HOST, SONAR_TOKEN, SONAR_ORGANIZATION):
            print("\n⚠️  Warning: Could not create project, will try to proceed...")
        
        print(f"\n[2/5] 📥 Cloning Repository")
        if not clone_repository(repo_url, repo_path):
            raise RuntimeError("❌ Failed to clone repository")
        
        print(f"\n[3/5] 🔍 Running SonarCloud Analysis")
        if not run_sonar_scanner(repo_path, project_key, SONAR_HOST, SONAR_TOKEN, SONAR_ORGANIZATION):
            raise RuntimeError("❌ Failed to run scanner")
        
        print(f"\n[4/5] 📊 Fetching Analysis Results")
        wait_for_analysis_completion(project_key, SONAR_HOST, SONAR_TOKEN)
        issues = fetch_issues(project_key, SONAR_HOST, SONAR_TOKEN)
        hotspots = fetch_hotspots(project_key, SONAR_HOST, SONAR_TOKEN)
        metrics = fetch_measures(project_key, SONAR_HOST, SONAR_TOKEN)
        
        print(f"\n[5/5] 📄 Generating Report")
        report_file, report_data = save_report(repo_name, project_key, issues, hotspots, metrics, SONAR_HOST)
        
        print_summary(report_data)
        
        print("\n" + "=" * 70)
        print("✅ Analysis Complete!")
        print("=" * 70)
        print(f"\n📁 Report saved to: {report_file}")
        print("\n🌐 View in SonarCloud:")
        print(f"   {SONAR_HOST}/dashboard?id={project_key}")
        print()
        
        return {
            "success": True,
            "report_file": str(report_file),
            "report_data": report_data,
            "project_key": project_key,
            "repo_url": repo_url,
            "owner": owner,
            "repo": repo
        }
        
    finally:
        print("\n🧹 Cleaning up temporary files...")
        os.chdir("/")
        shutil.rmtree(tmp_dir, ignore_errors=True)
        print("   ✅ Cleanup complete")
