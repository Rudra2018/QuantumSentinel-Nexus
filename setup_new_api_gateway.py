#!/usr/bin/env python3
"""
🌐 Setup API Gateway for New Complete Dashboard
==============================================
"""

import boto3
import json

def setup_new_api_gateway():
    """Setup API Gateway for the new complete dashboard"""
    api_client = boto3.client('apigateway', region_name='us-east-1')
    lambda_client = boto3.client('lambda', region_name='us-east-1')

    try:
        # Create new API Gateway
        api_response = api_client.create_rest_api(
            name='quantumsentinel-new-complete-api',
            description='New Complete QuantumSentinel Dashboard API',
            endpointConfiguration={'types': ['REGIONAL']}
        )

        api_id = api_response['id']
        print(f"✅ Created API Gateway: {api_id}")

        # Get the root resource
        resources = api_client.get_resources(restApiId=api_id)
        root_resource_id = None
        for resource in resources['items']:
            if resource['path'] == '/':
                root_resource_id = resource['id']
                break

        # Create {proxy+} resource
        proxy_resource = api_client.create_resource(
            restApiId=api_id,
            parentId=root_resource_id,
            pathPart='{proxy+}'
        )

        proxy_resource_id = proxy_resource['id']
        print(f"✅ Created proxy resource: {proxy_resource_id}")

        # Create ANY method for root resource
        api_client.put_method(
            restApiId=api_id,
            resourceId=root_resource_id,
            httpMethod='ANY',
            authorizationType='NONE'
        )

        # Create ANY method for proxy resource
        api_client.put_method(
            restApiId=api_id,
            resourceId=proxy_resource_id,
            httpMethod='ANY',
            authorizationType='NONE'
        )

        # Setup Lambda integration for root
        lambda_arn = f"arn:aws:lambda:us-east-1:077732578302:function:quantumsentinel-new-complete-dashboard"
        integration_uri = f"arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/{lambda_arn}/invocations"

        api_client.put_integration(
            restApiId=api_id,
            resourceId=root_resource_id,
            httpMethod='ANY',
            type='AWS_PROXY',
            integrationHttpMethod='POST',
            uri=integration_uri
        )

        # Setup Lambda integration for proxy
        api_client.put_integration(
            restApiId=api_id,
            resourceId=proxy_resource_id,
            httpMethod='ANY',
            type='AWS_PROXY',
            integrationHttpMethod='POST',
            uri=integration_uri
        )

        print("✅ Lambda integrations created")

        # Add Lambda permissions
        try:
            lambda_client.add_permission(
                FunctionName='quantumsentinel-new-complete-dashboard',
                StatementId='allow-api-gateway-root',
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

        # Deploy the API
        deployment = api_client.create_deployment(
            restApiId=api_id,
            stageName='prod',
            description='Production deployment for new complete dashboard'
        )

        print(f"✅ API deployed to prod stage")

        # Enable CORS
        try:
            # Add CORS to root resource
            api_client.put_method(
                restApiId=api_id,
                resourceId=root_resource_id,
                httpMethod='OPTIONS',
                authorizationType='NONE'
            )

            api_client.put_integration(
                restApiId=api_id,
                resourceId=root_resource_id,
                httpMethod='OPTIONS',
                type='MOCK',
                requestTemplates={
                    'application/json': '{"statusCode": 200}'
                }
            )

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

            print("✅ CORS enabled")
        except Exception as e:
            print(f"⚠️ CORS setup warning: {str(e)}")

        # Final deployment with CORS
        api_client.create_deployment(
            restApiId=api_id,
            stageName='prod',
            description='Production deployment with CORS enabled'
        )

        dashboard_url = f"https://{api_id}.execute-api.us-east-1.amazonaws.com/prod"

        print(f"\n🎉 NEW COMPLETE DASHBOARD DEPLOYED SUCCESSFULLY!")
        print(f"🌐 Dashboard URL: {dashboard_url}")
        print(f"📊 API Gateway ID: {api_id}")
        print(f"⚡ Lambda Function: quantumsentinel-new-complete-dashboard")

        return dashboard_url

    except Exception as e:
        print(f"❌ API Gateway setup failed: {str(e)}")
        return None

if __name__ == "__main__":
    setup_new_api_gateway()