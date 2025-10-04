#!/usr/bin/env python3
"""
🔧 Fix Only the Fetch URL in Dashboard
=====================================
Fix the relative URL to absolute URL without changing anything else
"""

import boto3
import json
import zipfile
import io

def fix_fetch_url():
    """Fix only the fetch URL in the existing Lambda function"""
    lambda_client = boto3.client('lambda', region_name='us-east-1')

    # Read the current working file
    with open('/Users/ankitthakur/Downloads/QuantumSentinel-Nexus/fix_file_processing.py', 'r') as f:
        code_content = f.read()

    # Extract only the lambda function code (skip the deployment part)
    start_marker = "fixed_processing_code = '''"
    end_marker = "'''"

    start_idx = code_content.find(start_marker) + len(start_marker)
    end_idx = code_content.find(end_marker, start_idx)

    lambda_code = code_content[start_idx:end_idx].strip()

    # Fix the JavaScript fetch URL
    old_fetch = "fetch('/upload', {"
    new_fetch = "fetch('https://992558rxmc.execute-api.us-east-1.amazonaws.com/prod/upload', {"

    fixed_lambda_code = lambda_code.replace(old_fetch, new_fetch)

    # Create zip file
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr('lambda_function.py', fixed_lambda_code)

    # Update Lambda function
    lambda_client.update_function_code(
        FunctionName='quantumsentinel-new-complete-dashboard',
        ZipFile=zip_buffer.getvalue()
    )

    print("✅ Fetch URL fixed successfully!")
    print("🔗 Updated to absolute URL: https://992558rxmc.execute-api.us-east-1.amazonaws.com/prod/upload")

if __name__ == "__main__":
    fix_fetch_url()