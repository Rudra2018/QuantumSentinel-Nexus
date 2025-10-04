#!/usr/bin/env python3
"""
🔧 Fix Upload Endpoint URL in Dashboard
======================================
Fix the relative URL to use the correct API Gateway endpoint
"""

import boto3
import json

def fix_upload_endpoint():
    """Fix upload endpoint URL in dashboard JavaScript"""
    lambda_client = boto3.client('lambda', region_name='us-east-1')

    # Get current function code
    response = lambda_client.get_function(FunctionName='quantumsentinel-new-complete-dashboard')

    # Read the current function code from fix_file_processing.py
    with open('/Users/ankitthakur/Downloads/QuantumSentinel-Nexus/fix_file_processing.py', 'r') as f:
        code_content = f.read()

    # Fix the JavaScript fetch URL
    old_fetch = "fetch('/upload', {"
    new_fetch = "fetch('https://992558rxmc.execute-api.us-east-1.amazonaws.com/prod/upload', {"

    fixed_code = code_content.replace(old_fetch, new_fetch)

    # Update Lambda function with fixed code
    lambda_client.update_function_code(
        FunctionName='quantumsentinel-new-complete-dashboard',
        ZipFile=create_zip_file(fixed_code)
    )

    print("✅ Upload endpoint URL fixed!")
    print("🔗 Updated fetch URL to: https://992558rxmc.execute-api.us-east-1.amazonaws.com/prod/upload")

def create_zip_file(code_content):
    """Create a zip file with the Lambda function code"""
    import zipfile
    import io

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr('lambda_function.py', code_content)

    return zip_buffer.getvalue()

if __name__ == "__main__":
    fix_upload_endpoint()