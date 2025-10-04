#!/usr/bin/env python3
"""
🔧 Fix 403 Forbidden API Gateway Integration
=============================================
Fix API Gateway integration and permissions
"""

import boto3

def fix_403_api_gateway():
    """Fix 403 errors by updating API Gateway integration"""
    api_client = boto3.client('apigateway', region_name='us-east-1')
    lambda_client = boto3.client('lambda', region_name='us-east-1')

    api_id = '992558rxmc'

    try:
        print("🔧 Fixing API Gateway integration...")

        # Get resources
        resources = api_client.get_resources(restApiId=api_id)
        root_resource_id = None
        proxy_resource_id = None

        for resource in resources['items']:
            if resource['path'] == '/':
                root_resource_id = resource['id']
                print(f"Found root resource: {root_resource_id}")
            elif resource['path'] == '/{proxy+}':
                proxy_resource_id = resource['id']
                print(f"Found proxy resource: {proxy_resource_id}")

        # Fix Lambda permissions - remove old and add new
        try:
            print("Removing old Lambda permissions...")
            lambda_client.remove_permission(
                FunctionName='quantumsentinel-new-complete-dashboard',
                StatementId='allow-api-gateway-invoke'
            )
        except Exception as e:
            print(f"Old permission removal: {str(e)}")

        try:
            print("Removing other old Lambda permissions...")
            lambda_client.remove_permission(
                FunctionName='quantumsentinel-new-complete-dashboard',
                StatementId='allow-api-gateway-root'
            )
        except Exception as e:
            print(f"Other permission removal: {str(e)}")

        # Add fresh Lambda permissions
        try:
            lambda_client.add_permission(
                FunctionName='quantumsentinel-new-complete-dashboard',
                StatementId='allow-api-gateway-all-methods',
                Action='lambda:InvokeFunction',
                Principal='apigateway.amazonaws.com',
                SourceArn=f"arn:aws:execute-api:us-east-1:077732578302:{api_id}/*/*/*"
            )
            print("✅ Fresh Lambda permissions added")
        except Exception as e:
            if 'already exists' in str(e):
                print("✅ Lambda permissions already exist")
            else:
                print(f"⚠️ Lambda permission error: {str(e)}")

        # Update Lambda integration for root resource
        if root_resource_id:
            lambda_arn = f"arn:aws:lambda:us-east-1:077732578302:function:quantumsentinel-new-complete-dashboard"
            integration_uri = f"arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/{lambda_arn}/invocations"

            try:
                print("Updating Lambda integration for root...")
                api_client.put_integration(
                    restApiId=api_id,
                    resourceId=root_resource_id,
                    httpMethod='ANY',
                    type='AWS_PROXY',
                    integrationHttpMethod='POST',
                    uri=integration_uri
                )
                print("✅ Root integration updated")
            except Exception as e:
                print(f"Root integration error: {str(e)}")

        # Update Lambda integration for proxy resource
        if proxy_resource_id:
            try:
                print("Updating Lambda integration for proxy...")
                api_client.put_integration(
                    restApiId=api_id,
                    resourceId=proxy_resource_id,
                    httpMethod='ANY',
                    type='AWS_PROXY',
                    integrationHttpMethod='POST',
                    uri=integration_uri
                )
                print("✅ Proxy integration updated")
            except Exception as e:
                print(f"Proxy integration error: {str(e)}")

        # Create a new deployment
        print("Creating new deployment...")
        deployment = api_client.create_deployment(
            restApiId=api_id,
            stageName='prod',
            description='Fix 403 Forbidden errors deployment'
        )
        print(f"✅ New deployment created: {deployment['id']}")

        # Test the API Gateway
        print("\n🧪 Testing API Gateway...")
        import subprocess
        import json

        test_payload = {
            "file_data": "dGVzdA==",  # "test" in base64
            "file_name": "test.txt",
            "file_type": "text/plain",
            "analysis_options": ["dast-analysis"]
        }

        # Test with curl
        curl_command = [
            'curl', '-X', 'POST',
            f'https://{api_id}.execute-api.us-east-1.amazonaws.com/prod/upload',
            '-H', 'Content-Type: application/json',
            '-d', json.dumps(test_payload),
            '-w', '%{http_code}',
            '-s'
        ]

        try:
            result = subprocess.run(curl_command, capture_output=True, text=True, timeout=30)
            print(f"Test response: {result.stdout}")
            print(f"Test stderr: {result.stderr}")
        except Exception as e:
            print(f"Test error: {str(e)}")

        print(f"\n🎉 API Gateway fixes applied!")
        print(f"🌐 Dashboard URL: https://{api_id}.execute-api.us-east-1.amazonaws.com/prod")

    except Exception as e:
        print(f"❌ API Gateway fix failed: {str(e)}")

if __name__ == "__main__":
    fix_403_api_gateway()