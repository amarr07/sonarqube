# mcphub

CLI tool for MCP server registry with SonarQube analysis.

## Installation

```bash
pip install -e .
```

## Configuration

Create `.env` file:

```
SONAR_TOKEN=your_token
SONAR_ORGANIZATION=your_org
S3_BUCKET_NAME=your_bucket
AWS_ACCESS_KEY_ID=your_key
AWS_SECRET_ACCESS_KEY=your_secret
AWS_REGION=ap-south-1
LAMBDA_BASE_URL=https://your-lambda-url.amazonaws.com
```

## Quick Start

### 1. Initialize project configuration
```bash
mcphub init
```
Creates `mcphub.json` with your server metadata.

### 2. Push to S3 with SonarQube analysis
```bash
mcphub push
# Or with explicit name:
mcphub push --name <server-name>
```

### 3. Pull to VS Code
```bash
mcphub pull --name <server-name>
```

## Commands

### `mcphub init`
Initialize `mcphub.json` configuration file. Prompts for:
- Server name
- Version
- Description
- Author
- Language
- License
- Entrypoint file
- Repository URL

### `mcphub push`
Analyze repository with SonarQube and push to S3.
- Reads from `mcphub.json` if available
- Runs full security analysis
- Saves reports locally
- Pushes metadata to S3

Options:
- `--name` - Server name (optional if mcphub.json exists)
- `--force` - Skip confirmation if exists
- `--bucket` - Custom S3 bucket

### `mcphub search`
Search for a server in S3 and display its JSON details.
- Fetches server metadata from S3
- Displays complete JSON configuration
- Shows available servers if not found

Options:
- `--name` - Server name (required)
- `--bucket` - Custom S3 bucket

Example:
```bash
mcphub search --name WeatherMCP
```

### `mcphub pull`
Add server from S3 to VS Code mcp.json.
- Fetches from S3
- Generates Lambda URL
- Updates VS Code config

Options:
- `--name` - Server name (required)
- `--bucket` - Custom S3 bucket

## Cross-Platform Support

Works automatically on:
- ✅ **macOS**: `~/Library/Application Support/Code/User/mcp.json`
- ✅ **Windows**: `%APPDATA%/Code/User/mcp.json`
- ✅ **Linux**: `~/.config/Code/User/mcp.json`
