import json
import boto3
from botocore.exceptions import ClientError

def get_s3_client():
    return boto3.client('s3')

def check_server_exists(bucket_name, server_name):
    s3 = get_s3_client()
    try:
        response = s3.get_object(Bucket=bucket_name, Key='mcp.json')
        content = response['Body'].read().decode('utf-8')
        mcp_data = json.loads(content)
        
        servers = mcp_data.get('servers', [])
        for server in servers:
            if server.get('name') == server_name:
                return True, mcp_data
        
        return False, mcp_data
    
    except s3.exceptions.NoSuchKey:
        return False, {"servers": []}
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchKey':
            return False, {"servers": []}
        raise

def add_server_to_mcp(bucket_name, server_data):
    s3 = get_s3_client()
    
    try:
        response = s3.get_object(Bucket=bucket_name, Key='mcp.json')
        content = response['Body'].read().decode('utf-8')
        mcp_data = json.loads(content)
    except (s3.exceptions.NoSuchKey, ClientError):
        mcp_data = {"servers": []}
    
    servers = mcp_data.get('servers', [])
    
    existing_server = None
    for s in servers:
        if s.get('name') == server_data['name']:
            existing_server = s
            break
    
    if existing_server and 'meta' in existing_server:
        server_data['meta']['created_at'] = existing_server['meta']['created_at']
    
    servers = [s for s in servers if s.get('name') != server_data['name']]
    servers.append(server_data)
    mcp_data['servers'] = servers
    
    s3.put_object(
        Bucket=bucket_name,
        Key='mcp.json',
        Body=json.dumps(mcp_data, indent=2),
        ContentType='application/json'
    )
    
    return True

def get_mcp_json(bucket_name):
    s3 = get_s3_client()
    try:
        response = s3.get_object(Bucket=bucket_name, Key='mcp.json')
        content = response['Body'].read().decode('utf-8')
        return json.loads(content)
    except (s3.exceptions.NoSuchKey, ClientError):
        return {"servers": []}
