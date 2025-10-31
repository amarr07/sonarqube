#!/usr/bin/env python3

import click
import os
import sys
import platform
from pathlib import Path
from . import sonarqube
from . import s3_handler

def get_vscode_mcp_path():
    """Get VS Code mcp.json path based on operating system"""
    system = platform.system()
    
    if system == "Darwin":
        return Path.home() / "Library/Application Support/Code/User/mcp.json"
    elif system == "Windows":
        return Path.home() / "AppData/Roaming/Code/User/mcp.json"
    elif system == "Linux":
        return Path.home() / ".config/Code/User/mcp.json"
    else:
        raise ValueError(f"Unsupported operating system: {system}")

@click.group()
@click.version_option(version='1.0.0', prog_name='mcphub')
def cli():
    """MCP Hub CLI - Manage MCP servers with SonarQube analysis"""
    pass

@cli.command()
@click.option('--name', required=True, help='Name of the MCP server to search')
@click.option('--bucket', help='S3 bucket name (default: from S3_BUCKET_NAME env var)')
def search(name, bucket):
    """Search for a server in S3 and display its JSON details"""
    import json
    
    env_path = Path.cwd() / ".env"
    if not env_path.exists():
        click.echo("❌ Error: .env file not found in current directory")
        sys.exit(1)
    
    if not bucket:
        sonarqube.load_env_file(env_path)
        bucket = os.environ.get('S3_BUCKET_NAME') or os.environ.get('AWS_BUCKET')
        if not bucket:
            click.echo("❌ Error: S3_BUCKET_NAME not found in .env file or --bucket option")
            sys.exit(1)
    
    click.echo(f"\n🔍 Searching for server '{name}' in S3 bucket '{bucket}'...\n")
    
    try:
        mcp_data = s3_handler.get_mcp_json(bucket)
        servers = mcp_data.get('servers', [])
        
        server = None
        for s in servers:
            if s.get('name') == name:
                server = s
                break
        
        if not server:
            click.echo(f"❌ Server '{name}' not found in S3 bucket")
            click.echo(f"\n💡 Available servers ({len(servers)} total):")
            for s in servers:
                click.echo(f"   • {s.get('name')}")
            sys.exit(1)
        
        click.echo("=" * 70)
        click.echo(f"✅ Found: {name}")
        click.echo("=" * 70)
        click.echo("\n📄 Server Details (JSON):\n")
        click.echo(json.dumps(server, indent=2))
        click.echo("\n" + "=" * 70)
        
    except Exception as e:
        click.echo(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

@cli.command()
def init():
    """Initialize mcphub.json configuration file"""
    import json
    from datetime import datetime
    
    config_file = Path.cwd() / "mcphub.json"
    
    if config_file.exists():
        click.echo(f"⚠️  mcphub.json already exists")
        if not click.confirm("Do you want to overwrite it?"):
            click.echo("❌ Aborted")
            sys.exit(0)
    
    click.echo("\n📝 Initialize MCP Server Configuration")
    click.echo("=" * 50)
    
    repo_url = click.prompt("\n🔗 Repository URL (GitHub)", default="")
    if repo_url:
        from . import sonarqube as sq
        owner, repo = sq.extract_repo_name(repo_url)
        default_name = repo if repo else ""
    else:
        default_name = Path.cwd().name
        owner = ""
        repo = ""
    
    name = click.prompt("📦 Server name", default=default_name)
    version = click.prompt("🏷️  Version", default="1.0.0")
    description = click.prompt("📄 Description", default=f"MCP server for {name}")
    author = click.prompt("👤 Author", default="")
    lang = click.prompt("💻 Language", default="Python")
    license_type = click.prompt("📜 License", default="MIT")
    entrypoint = click.prompt("🚪 Entrypoint file", default="main.py")
    
    if not repo_url:
        repo_url = click.prompt("🔗 Repository URL", default="")
    
    add_pricing = click.confirm("\n💰 Add pricing information?", default=False)
    
    config = {
        "name": name,
        "version": version,
        "description": description,
        "author": author,
        "lang": lang,
        "license": license_type,
        "entrypoint": entrypoint,
        "repository": {
            "type": "git",
            "url": repo_url
        }
    }
    
    if add_pricing:
        currency = click.prompt("💵 Currency", default="USD")
        amount = click.prompt("💲 Amount", type=float, default=0.0)
        config["pricing"] = {
            "currency": currency,
            "amount": amount
        }
    
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)
    
    click.echo("\n" + "=" * 50)
    click.echo("✅ Configuration saved!")
    click.echo("=" * 50)
    click.echo(f"\n📁 Created: {config_file}")
    click.echo("\n💡 Next steps:")
    click.echo(f"   1. mcphub push --name {name}")
    click.echo(f"   2. mcphub pull --name {name}")

@cli.command()
@click.option('--name', help='Name of the MCP server (reads from mcphub.json if not provided)')
@click.option('--bucket', help='S3 bucket name (default: from AWS_BUCKET env var)')
@click.option('--force', is_flag=True, help='Skip confirmation if server exists')
def push(name, bucket, force):
    """Push server to S3 with SonarQube analysis"""
    import json
    
    config_file = Path.cwd() / "mcphub.json"
    config = None
    
    if config_file.exists():
        with open(config_file, 'r') as f:
            config = json.load(f)
        click.echo(f"📄 Found mcphub.json configuration")
        if not name:
            name = config.get('name')
            click.echo(f"📦 Using name from config: {name}")
    
    if not name:
        click.echo("❌ Error: --name required (or create mcphub.json with 'mcphub init')")
        sys.exit(1)
    
    env_path = Path.cwd() / ".env"
    if not env_path.exists():
        click.echo("❌ Error: .env file not found in current directory")
        click.echo("\nCreate a .env file with:")
        click.echo("  SONAR_TOKEN=your_token_here")
        click.echo("  SONAR_ORGANIZATION=your_org_here")
        click.echo("  AWS_BUCKET=your_bucket_name")
        sys.exit(1)
    
    if not bucket:
        sonarqube.load_env_file(env_path)
        bucket = os.environ.get('S3_BUCKET_NAME') or os.environ.get('AWS_BUCKET')
        if not bucket:
            click.echo("❌ Error: S3_BUCKET_NAME not found in .env file or --bucket option")
            sys.exit(1)
    
    click.echo(f"\n🔍 Checking if server '{name}' exists in S3 bucket '{bucket}'...")
    
    try:
        exists, mcp_data = s3_handler.check_server_exists(bucket, name)
        
        if exists:
            click.echo(f"⚠️  Server '{name}' already exists in mcp.json")
            if not force and not click.confirm("Do you want to overwrite it?"):
                click.echo("❌ Aborted")
                sys.exit(0)
            if force:
                click.echo("✅ Force flag set, will overwrite existing server")
    except Exception as e:
        click.echo(f"⚠️  Could not check S3 bucket: {str(e)}")
        if not click.confirm("Continue anyway?"):
            sys.exit(1)
    
    if config:
        click.echo(f"\n📝 Using configuration from mcphub.json:")
        version = config.get('version', '1.0.0')
        description = config.get('description', '')
        author = config.get('author', '')
        lang = config.get('lang', 'Python')
        license_type = config.get('license', 'MIT')
        entrypoint = config.get('entrypoint', 'main.py')
        repo_url = config.get('repository', {}).get('url', '')
        
        click.echo(f"   Version: {version}")
        click.echo(f"   Description: {description}")
        click.echo(f"   Author: {author}")
        click.echo(f"   Repository: {repo_url}")
    else:
        click.echo(f"\n📝 Please provide information for server '{name}':")
        
        version = click.prompt("Version", default="1.0.0")
        description = click.prompt("Description")
        author = click.prompt("Author")
        lang = click.prompt("Language", default="Python")
        license_type = click.prompt("License", default="MIT")
        entrypoint = click.prompt("Entrypoint file", default="main.py")
        repo_url = click.prompt("Repository URL (GitHub)")
    
    click.echo(f"\n🚀 Starting SonarQube analysis for {repo_url}...")
    
    try:
        result = sonarqube.run_analysis(repo_url, env_path)
        
        if not result['success']:
            click.echo("❌ Analysis failed")
            sys.exit(1)
        
        report_data = result['report_data']
        
        from datetime import datetime
        current_time = datetime.now().astimezone().isoformat()
        
        server_entry = {
            "name": name,
            "version": version,
            "description": description,
            "author": author,
            "lang": lang,
            "license": license_type,
            "entrypoint": entrypoint,
            "repository": {
                "type": "git",
                "url": repo_url
            },
            "meta": {
                "created_at": current_time,
                "updated_at": current_time
            }
        }
        
        if config and 'pricing' in config:
            click.echo("\n💡 Note: Pricing information is stored locally only, not pushed to S3")
        
        click.echo(f"\n📤 Pushing server entry to S3 bucket '{bucket}'...")
        
        s3_handler.add_server_to_mcp(bucket, server_entry)
        
        click.echo("\n" + "=" * 70)
        click.echo("✅ Success!")
        click.echo("=" * 70)
        click.echo(f"\n✅ Server '{name}' has been added to S3 mcp.json")
        click.echo(f"✅ SonarQube analysis saved locally: {result['report_file']}")
        click.echo(f"✅ View analysis in SonarCloud: {report_data['metadata']['sonarcloud_url']}")
        click.echo(f"\n💡 Note: SonarQube data is saved in local reports, not pushed to S3")
        
    except Exception as e:
        click.echo(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

@cli.command()
@click.option('--name', required=True, help='Name of the MCP server to pull')
@click.option('--bucket', help='S3 bucket name (default: from S3_BUCKET_NAME env var)')
def pull(name, bucket):
    """Pull a server from S3 and add to VS Code mcp.json"""
    import json
    from pathlib import Path
    
    env_path = Path.cwd() / ".env"
    if not env_path.exists():
        click.echo("❌ Error: .env file not found in current directory")
        sys.exit(1)
    
    if not bucket:
        sonarqube.load_env_file(env_path)
        bucket = os.environ.get('S3_BUCKET_NAME') or os.environ.get('AWS_BUCKET')
        if not bucket:
            click.echo("❌ Error: S3_BUCKET_NAME not found in .env file or --bucket option")
            sys.exit(1)
    
    sonarqube.load_env_file(env_path)
    lambda_base_url = os.environ.get('LAMBDA_BASE_URL')
    if not lambda_base_url:
        click.echo("❌ Error: LAMBDA_BASE_URL not found in .env file")
        click.echo("Add to .env: LAMBDA_BASE_URL=https://your-lambda-url.amazonaws.com")
        sys.exit(1)
    
    click.echo(f"\n🔍 Fetching server '{name}' from S3 bucket '{bucket}'...")
    
    try:
        mcp_data = s3_handler.get_mcp_json(bucket)
        servers = mcp_data.get('servers', [])
        
        server = None
        for s in servers:
            if s.get('name') == name:
                server = s
                break
        
        if not server:
            click.echo(f"❌ Error: Server '{name}' not found in S3 bucket")
            click.echo("\nAvailable servers:")
            for s in servers:
                click.echo(f"  • {s.get('name')}")
            sys.exit(1)
        
        click.echo(f"✅ Found server: {name}")
        click.echo(f"   Description: {server.get('description')}")
        click.echo(f"   Author: {server.get('author')}")
        click.echo(f"   Repository: {server.get('repository', {}).get('url')}")
        
        try:
            vscode_mcp_path = get_vscode_mcp_path()
        except ValueError as e:
            click.echo(f"❌ Error: {str(e)}")
            sys.exit(1)
        
        if not vscode_mcp_path.exists():
            click.echo(f"❌ Error: VS Code mcp.json not found at {vscode_mcp_path}")
            click.echo(f"\n💡 Expected location for {platform.system()}:")
            click.echo(f"   {vscode_mcp_path}")
            sys.exit(1)
        
        with open(vscode_mcp_path, 'r') as f:
            vscode_mcp = json.load(f)
        
        if 'servers' not in vscode_mcp:
            vscode_mcp['servers'] = {}
        
        server_url = f"{lambda_base_url}/{name}"
        
        if name in vscode_mcp['servers']:
            click.echo(f"\n⚠️  Server '{name}' already exists in VS Code mcp.json")
            if not click.confirm("Do you want to overwrite it?"):
                click.echo("❌ Aborted")
                sys.exit(0)
        
        vscode_mcp['servers'][name] = {
            "url": server_url
        }
        
        with open(vscode_mcp_path, 'w') as f:
            json.dump(vscode_mcp, f, indent='\t')
        
        click.echo("\n" + "=" * 70)
        click.echo("✅ Success!")
        click.echo("=" * 70)
        click.echo(f"\n✅ Server '{name}' added to VS Code mcp.json")
        click.echo(f"✅ URL: {server_url}")
        click.echo(f"\n📍 Location: {vscode_mcp_path}")
        click.echo("\n💡 Restart VS Code to load the new server")
        
    except Exception as e:
        click.echo(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

def main():
    cli()

if __name__ == '__main__':
    main()
