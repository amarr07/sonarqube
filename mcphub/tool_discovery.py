import os
import json
import re
from pathlib import Path

def discover_tools_from_repo(repo_path):
    """
    Discover MCP tools from a repository by analyzing Python files.
    Returns dict with tool_count and tool_names list.
    """
    tools = []
    
    python_files = list(Path(repo_path).rglob("*.py"))
    
    for py_file in python_files:
        try:
            with open(py_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            file_tools = extract_tools_from_python(content)
            tools.extend(file_tools)
        except Exception:
            continue
    
    unique_tools = list(set(tools))
    
    return {
        "tool_count": len(unique_tools),
        "tool_names": sorted(unique_tools)
    }

def extract_tools_from_python(content):
    """
    Extract MCP tool names from Python code.
    Looks for @server.call_tool, @mcp.tool, and similar patterns.
    """
    tools = []
    
    tool_patterns = [
        r'@server\.call_tool\(["\']([^"\']+)["\']\)',
        r'@mcp\.tool\(["\']([^"\']+)["\']\)',
        r'@server\.tool\(["\']([^"\']+)["\']\)',
        r'Tool\(name=["\']([^"\']+)["\']\)',
        r'name=["\']([^"\']+)["\'].*type=["\']tool["\']',
        r'def\s+(\w+).*@.*tool',
    ]
    
    for pattern in tool_patterns:
        matches = re.findall(pattern, content, re.MULTILINE)
        tools.extend(matches)
    
    if '"tools"' in content or "'tools'" in content:
        try:
            tools_section = re.search(r'["\']tools["\']\s*:\s*\[(.*?)\]', content, re.DOTALL)
            if tools_section:
                tool_names = re.findall(r'["\']name["\']\s*:\s*["\']([^"\']+)["\']', tools_section.group(1))
                tools.extend(tool_names)
        except Exception:
            pass
    
    tools = [t for t in tools if t and not t.startswith('_') and len(t) > 1]
    
    return tools

def discover_tools_from_package_json(repo_path):
    """
    Check if there's a package.json with MCP tool definitions (for Node.js servers)
    """
    package_json = Path(repo_path) / "package.json"
    
    if not package_json.exists():
        return {"tool_count": 0, "tool_names": []}
    
    try:
        with open(package_json, 'r') as f:
            data = json.load(f)
        
        tools = []
        
        if 'mcp' in data and 'tools' in data['mcp']:
            tools = [tool.get('name') for tool in data['mcp']['tools'] if 'name' in tool]
        
        return {
            "tool_count": len(tools),
            "tool_names": sorted(tools)
        }
    except Exception:
        return {"tool_count": 0, "tool_names": []}
