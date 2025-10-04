#!/usr/bin/env python3
"""
🔧 Fix CORS and Permissions for API Gateway
===========================================
"""

import boto3
import json

def fix_cors_and_permissions():
    """Fix CORS and permissions issues"""
    lambda_client = boto3.client('lambda', region_name='us-east-1')
    api_client = boto3.client('apigateway', region_name='us-east-1')

    api_id = '992558rxmc'

    try:
        # Add Lambda permissions for API Gateway
        try:
            lambda_client.add_permission(
                FunctionName='quantumsentinel-new-complete-dashboard',
                StatementId='allow-api-gateway-invoke',
                Action='lambda:InvokeFunction',
                Principal='apigateway.amazonaws.com',
                SourceArn=f"arn:aws:execute-api:us-east-1:077732578302:{api_id}/*/*"
            )
            print("✅ Lambda permissions added")
        except Exception as e:
            if 'already exists' in str(e):
                print("✅ Lambda permissions already exist")
            else:
                print(f"⚠️ Lambda permission warning: {str(e)}")

        # Get resources
        resources = api_client.get_resources(restApiId=api_id)
        root_resource_id = None
        proxy_resource_id = None

        for resource in resources['items']:
            if resource['path'] == '/':
                root_resource_id = resource['id']
            elif resource['path'] == '/{proxy+}':
                proxy_resource_id = resource['id']

        print(f"Root resource: {root_resource_id}")
        print(f"Proxy resource: {proxy_resource_id}")

        # Enable CORS for root resource
        if root_resource_id:
            try:
                # Add OPTIONS method
                api_client.put_method(
                    restApiId=api_id,
                    resourceId=root_resource_id,
                    httpMethod='OPTIONS',
                    authorizationType='NONE'
                )
                print("✅ OPTIONS method added to root")
            except Exception as e:
                if 'already exists' in str(e):
                    print("✅ OPTIONS method already exists on root")
                else:
                    print(f"⚠️ OPTIONS method warning: {str(e)}")

            # Add MOCK integration for OPTIONS
            try:
                api_client.put_integration(
                    restApiId=api_id,
                    resourceId=root_resource_id,
                    httpMethod='OPTIONS',
                    type='MOCK',
                    requestTemplates={
                        'application/json': '{"statusCode": 200}'
                    }
                )
                print("✅ MOCK integration added to root OPTIONS")
            except Exception as e:
                print(f"⚠️ MOCK integration warning: {str(e)}")

            # Add method response for OPTIONS
            try:
                api_client.put_method_response(
                    restApiId=api_id,
                    resourceId=root_resource_id,
                    httpMethod='OPTIONS',
                    statusCode='200',
                    responseParameters={
                        'method.response.header.Access-Control-Allow-Headers': False,
                        'method.response.header.Access-Control-Allow-Methods': False,
                        'method.response.header.Access-Control-Allow-Origin': False
                    }
                )
                print("✅ Method response added to root OPTIONS")
            except Exception as e:
                print(f"⚠️ Method response warning: {str(e)}")

            # Add integration response for OPTIONS
            try:
                api_client.put_integration_response(
                    restApiId=api_id,
                    resourceId=root_resource_id,
                    httpMethod='OPTIONS',
                    statusCode='200',
                    responseParameters={
                        'method.response.header.Access-Control-Allow-Headers': "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'",
                        'method.response.header.Access-Control-Allow-Methods': "'GET,POST,OPTIONS'",
                        'method.response.header.Access-Control-Allow-Origin': "'*'"
                    }
                )
                print("✅ Integration response added to root OPTIONS")
            except Exception as e:
                print(f"⚠️ Integration response warning: {str(e)}")

        # Enable CORS for proxy resource
        if proxy_resource_id:
            try:
                # Add OPTIONS method
                api_client.put_method(
                    restApiId=api_id,
                    resourceId=proxy_resource_id,
                    httpMethod='OPTIONS',
                    authorizationType='NONE'
                )
                print("✅ OPTIONS method added to proxy")
            except Exception as e:
                if 'already exists' in str(e):
                    print("✅ OPTIONS method already exists on proxy")
                else:
                    print(f"⚠️ OPTIONS method warning: {str(e)}")

            # Add MOCK integration for OPTIONS
            try:
                api_client.put_integration(
                    restApiId=api_id,
                    resourceId=proxy_resource_id,
                    httpMethod='OPTIONS',
                    type='MOCK',
                    requestTemplates={
                        'application/json': '{"statusCode": 200}'
                    }
                )
                print("✅ MOCK integration added to proxy OPTIONS")
            except Exception as e:
                print(f"⚠️ MOCK integration warning: {str(e)}")

            # Add method response for OPTIONS
            try:
                api_client.put_method_response(
                    restApiId=api_id,
                    resourceId=proxy_resource_id,
                    httpMethod='OPTIONS',
                    statusCode='200',
                    responseParameters={
                        'method.response.header.Access-Control-Allow-Headers': False,
                        'method.response.header.Access-Control-Allow-Methods': False,
                        'method.response.header.Access-Control-Allow-Origin': False
                    }
                )
                print("✅ Method response added to proxy OPTIONS")
            except Exception as e:
                print(f"⚠️ Method response warning: {str(e)}")

            # Add integration response for OPTIONS
            try:
                api_client.put_integration_response(
                    restApiId=api_id,
                    resourceId=proxy_resource_id,
                    httpMethod='OPTIONS',
                    statusCode='200',
                    responseParameters={
                        'method.response.header.Access-Control-Allow-Headers': "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'",
                        'method.response.header.Access-Control-Allow-Methods': "'GET,POST,OPTIONS'",
                        'method.response.header.Access-Control-Allow-Origin': "'*'"
                    }
                )
                print("✅ Integration response added to proxy OPTIONS")
            except Exception as e:
                print(f"⚠️ Integration response warning: {str(e)}")

        # Create new deployment
        deployment = api_client.create_deployment(
            restApiId=api_id,
            stageName='prod',
            description='CORS and permissions fix deployment'
        )

        print(f"✅ New deployment created: {deployment['id']}")
        print(f"🌐 Dashboard URL: https://{api_id}.execute-api.us-east-1.amazonaws.com/prod")

        return f"https://{api_id}.execute-api.us-east-1.amazonaws.com/prod"

    except Exception as e:
        print(f"❌ CORS fix failed: {str(e)}")
        return None

if __name__ == "__main__":
    fix_cors_and_permissions()