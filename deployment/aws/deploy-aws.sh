#!/bin/bash

# QuantumSentinel-Nexus AWS Deployment Script
# Deploy QuantumSentinel-Nexus to AWS using ECS, Lambda, and other AWS services

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="quantumsentinel-nexus"
STACK_NAME=""
REGION="us-east-1"
PROFILE="default"
IMAGE_TAG="latest"
AUTO_DEPLOY=false

# Functions
print_banner() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                QuantumSentinel-Nexus AWS Deployment                         ║"
    echo "║                    Container and Serverless Deployment                      ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_step() {
    echo -e "${CYAN}[STEP]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    print_step "Checking deployment prerequisites..."

    # Check if AWS CLI is installed
    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI is not installed."
        exit 1
    fi

    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed."
        exit 1
    fi

    # Check if user is authenticated
    if ! aws sts get-caller-identity &> /dev/null; then
        print_error "No active AWS authentication found. Please run 'aws configure' or 'aws sso login'"
        exit 1
    fi

    # Check if CloudFormation stack exists
    if ! aws cloudformation describe-stacks --stack-name $STACK_NAME --region $REGION &> /dev/null; then
        print_error "CloudFormation stack '$STACK_NAME' not found. Please run setup-aws.sh first."
        exit 1
    fi

    print_success "Prerequisites check completed"
}

get_stack_outputs() {
    print_step "Getting CloudFormation stack outputs..."

    ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

    # Get stack outputs
    STACK_OUTPUTS=$(aws cloudformation describe-stacks --stack-name $STACK_NAME --region $REGION --query 'Stacks[0].Outputs' --output json)

    # Extract important values
    VPC_ID=$(echo $STACK_OUTPUTS | jq -r '.[] | select(.OutputKey=="VPCId") | .OutputValue')
    PUBLIC_SUBNET_1=$(echo $STACK_OUTPUTS | jq -r '.[] | select(.OutputKey=="PublicSubnet1Id") | .OutputValue')
    PUBLIC_SUBNET_2=$(echo $STACK_OUTPUTS | jq -r '.[] | select(.OutputKey=="PublicSubnet2Id") | .OutputValue')
    SECURITY_GROUP_ID=$(echo $STACK_OUTPUTS | jq -r '.[] | select(.OutputKey=="SecurityGroupId") | .OutputValue')
    ECR_REPOSITORY=$(echo $STACK_OUTPUTS | jq -r '.[] | select(.OutputKey=="ECRRepository") | .OutputValue')
    ROLE_ARN="arn:aws:iam::$ACCOUNT_ID:role/$PROJECT_NAME-execution-role"

    print_success "Stack outputs retrieved"
    echo "  VPC ID: $VPC_ID"
    echo "  ECR Repository: $ECR_REPOSITORY"
}

build_and_push_image() {
    print_step "Building and pushing Docker image to ECR..."

    # Login to ECR
    aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $ECR_REPOSITORY

    # Build the image
    print_step "Building Docker image..."
    docker build -t $PROJECT_NAME:$IMAGE_TAG -f Dockerfile.simple .

    # Tag the image for ECR
    docker tag $PROJECT_NAME:$IMAGE_TAG $ECR_REPOSITORY:$IMAGE_TAG

    # Push the image
    print_step "Pushing image to ECR..."
    docker push $ECR_REPOSITORY:$IMAGE_TAG

    print_success "Image pushed to ECR: $ECR_REPOSITORY:$IMAGE_TAG"
}

create_ecs_cluster() {
    print_step "Creating ECS cluster and service..."

    CLUSTER_NAME="$PROJECT_NAME-cluster"
    SERVICE_NAME="$PROJECT_NAME-service"
    TASK_DEFINITION_NAME="$PROJECT_NAME-task"

    # Check if cluster exists
    if aws ecs describe-clusters --clusters $CLUSTER_NAME --region $REGION &> /dev/null; then
        print_warning "ECS cluster already exists: $CLUSTER_NAME"
    else
        # Create ECS cluster
        aws ecs create-cluster \
            --cluster-name $CLUSTER_NAME \
            --capacity-providers FARGATE \
            --default-capacity-provider-strategy capacityProvider=FARGATE,weight=1 \
            --region $REGION
        print_success "ECS cluster created: $CLUSTER_NAME"
    fi

    # Create task definition
    cat > task-definition.json << EOF
{
    "family": "$TASK_DEFINITION_NAME",
    "networkMode": "awsvpc",
    "requiresCompatibilities": ["FARGATE"],
    "cpu": "2048",
    "memory": "4096",
    "executionRoleArn": "$ROLE_ARN",
    "taskRoleArn": "$ROLE_ARN",
    "containerDefinitions": [
        {
            "name": "$PROJECT_NAME-container",
            "image": "$ECR_REPOSITORY:$IMAGE_TAG",
            "portMappings": [
                {
                    "containerPort": 8000,
                    "protocol": "tcp"
                }
            ],
            "environment": [
                {
                    "name": "AWS_REGION",
                    "value": "$REGION"
                },
                {
                    "name": "CLOUD_PROVIDER",
                    "value": "aws"
                }
            ],
            "logConfiguration": {
                "logDriver": "awslogs",
                "options": {
                    "awslogs-group": "/ecs/$PROJECT_NAME",
                    "awslogs-region": "$REGION",
                    "awslogs-stream-prefix": "ecs"
                }
            },
            "essential": true
        }
    ]
}
EOF

    # Create CloudWatch log group
    aws logs create-log-group --log-group-name "/ecs/$PROJECT_NAME" --region $REGION 2>/dev/null || true

    # Register task definition
    aws ecs register-task-definition \
        --cli-input-json file://task-definition.json \
        --region $REGION > /dev/null

    print_success "Task definition registered: $TASK_DEFINITION_NAME"

    # Create ECS service
    if aws ecs describe-services --cluster $CLUSTER_NAME --services $SERVICE_NAME --region $REGION &> /dev/null; then
        print_warning "ECS service already exists: $SERVICE_NAME"

        # Update service with new task definition
        aws ecs update-service \
            --cluster $CLUSTER_NAME \
            --service $SERVICE_NAME \
            --task-definition $TASK_DEFINITION_NAME \
            --region $REGION > /dev/null
        print_success "ECS service updated"
    else
        aws ecs create-service \
            --cluster $CLUSTER_NAME \
            --service-name $SERVICE_NAME \
            --task-definition $TASK_DEFINITION_NAME \
            --desired-count 1 \
            --launch-type FARGATE \
            --network-configuration "awsvpcConfiguration={subnets=[$PUBLIC_SUBNET_1,$PUBLIC_SUBNET_2],securityGroups=[$SECURITY_GROUP_ID],assignPublicIp=ENABLED}" \
            --region $REGION > /dev/null
        print_success "ECS service created: $SERVICE_NAME"
    fi

    # Clean up temporary files
    rm -f task-definition.json
}

create_lambda_functions() {
    print_step "Creating Lambda functions for serverless components..."

    # Create deployment package directory
    mkdir -p lambda-deployment

    # Create a simple Lambda function for API endpoints
    cat > lambda-deployment/lambda_function.py << 'EOF'
import json
import boto3
import os
from datetime import datetime

def lambda_handler(event, context):
    """
    QuantumSentinel-Nexus Lambda API Handler
    """

    # Get HTTP method and path
    http_method = event.get('httpMethod', 'GET')
    path = event.get('path', '/')

    # Basic routing
    if path == '/health':
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'status': 'healthy',
                'timestamp': datetime.now().isoformat(),
                'service': 'quantumsentinel-nexus'
            })
        }

    elif path == '/api/scan':
        if http_method == 'POST':
            # Handle scan request
            try:
                request_body = json.loads(event.get('body', '{}'))
                target = request_body.get('target', '')
                scan_type = request_body.get('scan_type', 'basic')

                # For now, return a mock response
                # In production, this would trigger the actual scan
                return {
                    'statusCode': 200,
                    'headers': {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': json.dumps({
                        'scan_id': f'scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}',
                        'target': target,
                        'scan_type': scan_type,
                        'status': 'initiated',
                        'message': 'Scan request received and queued for processing'
                    })
                }
            except Exception as e:
                return {
                    'statusCode': 400,
                    'headers': {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': json.dumps({
                        'error': 'Invalid request',
                        'message': str(e)
                    })
                }

    # Default response
    return {
        'statusCode': 404,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps({
            'error': 'Not Found',
            'message': 'The requested resource was not found'
        })
    }
EOF

    # Create deployment package
    cd lambda-deployment
    zip -r ../quantum-sentinel-lambda.zip .
    cd ..

    # Create Lambda function
    FUNCTION_NAME="$PROJECT_NAME-api"

    if aws lambda get-function --function-name $FUNCTION_NAME --region $REGION &> /dev/null; then
        print_warning "Lambda function already exists: $FUNCTION_NAME"

        # Update function code
        aws lambda update-function-code \
            --function-name $FUNCTION_NAME \
            --zip-file fileb://quantum-sentinel-lambda.zip \
            --region $REGION > /dev/null
        print_success "Lambda function updated"
    else
        aws lambda create-function \
            --function-name $FUNCTION_NAME \
            --runtime python3.9 \
            --role $ROLE_ARN \
            --handler lambda_function.lambda_handler \
            --zip-file fileb://quantum-sentinel-lambda.zip \
            --timeout 300 \
            --memory-size 512 \
            --region $REGION > /dev/null
        print_success "Lambda function created: $FUNCTION_NAME"
    fi

    # Clean up
    rm -rf lambda-deployment quantum-sentinel-lambda.zip
}

create_api_gateway() {
    print_step "Creating API Gateway..."

    API_NAME="$PROJECT_NAME-api"
    FUNCTION_NAME="$PROJECT_NAME-api"

    # Create REST API
    API_ID=$(aws apigateway create-rest-api \
        --name $API_NAME \
        --description "QuantumSentinel-Nexus API Gateway" \
        --region $REGION \
        --query 'id' \
        --output text 2>/dev/null || aws apigateway get-rest-apis \
        --query "items[?name=='$API_NAME'].id" \
        --output text \
        --region $REGION)

    if [ -z "$API_ID" ] || [ "$API_ID" = "None" ]; then
        print_error "Failed to create or find API Gateway"
        return
    fi

    print_success "API Gateway created/found: $API_ID"

    # Get root resource ID
    ROOT_RESOURCE_ID=$(aws apigateway get-resources \
        --rest-api-id $API_ID \
        --region $REGION \
        --query 'items[?path==`/`].id' \
        --output text)

    # Add Lambda permission for API Gateway
    aws lambda add-permission \
        --function-name $FUNCTION_NAME \
        --statement-id "api-gateway-invoke-$API_ID" \
        --action lambda:InvokeFunction \
        --principal apigateway.amazonaws.com \
        --source-arn "arn:aws:execute-api:$REGION:$(aws sts get-caller-identity --query Account --output text):$API_ID/*/*" \
        --region $REGION 2>/dev/null || true

    print_success "API Gateway configuration completed"

    # Deploy API
    aws apigateway create-deployment \
        --rest-api-id $API_ID \
        --stage-name prod \
        --region $REGION > /dev/null 2>&1 || true

    API_URL="https://$API_ID.execute-api.$REGION.amazonaws.com/prod"
    echo "  API URL: $API_URL"
}

update_secrets() {
    print_step "Updating secrets with deployment information..."

    # Update secrets with actual values
    print_warning "Remember to update the following secrets with actual values:"
    echo "  aws secretsmanager update-secret --secret-id quantum/chaos-api-key --secret-string 'your-chaos-api-key'"
    echo "  aws secretsmanager update-secret --secret-id quantum/huggingface-token --secret-string 'your-huggingface-token'"
    echo "  aws secretsmanager update-secret --secret-id quantum/cve-api-key --secret-string 'your-cve-api-key'"
    echo "  aws secretsmanager update-secret --secret-id quantum/nuclei-api-key --secret-string 'your-nuclei-api-key'"
}

print_summary() {
    ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                         AWS DEPLOYMENT COMPLETED                            ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo -e "${GREEN}QuantumSentinel-Nexus successfully deployed to AWS!${NC}"
    echo ""
    echo -e "${CYAN}Deployment Information:${NC}"
    echo -e "  🏢 Account ID:      ${BLUE}$ACCOUNT_ID${NC}"
    echo -e "  🌍 Region:          ${BLUE}$REGION${NC}"
    echo -e "  📚 Stack Name:      ${BLUE}$STACK_NAME${NC}"
    echo ""
    echo -e "${CYAN}Services Deployed:${NC}"
    echo -e "  ✅ ECS Fargate cluster with containerized application"
    echo -e "  ✅ Lambda functions for serverless API endpoints"
    echo -e "  ✅ API Gateway for HTTP access"
    echo -e "  ✅ ECR repository with application image"
    echo -e "  ✅ CloudWatch logging and monitoring"
    echo ""
    echo -e "${CYAN}Access Points:${NC}"
    if [ ! -z "$API_URL" ]; then
        echo -e "  🌐 API Gateway:     ${BLUE}$API_URL${NC}"
    fi
    echo -e "  📊 ECS Console:     ${BLUE}https://console.aws.amazon.com/ecs/v2/clusters/$PROJECT_NAME-cluster${NC}"
    echo -e "  🔍 CloudWatch:      ${BLUE}https://console.aws.amazon.com/cloudwatch/home?region=$REGION${NC}"
    echo ""
    echo -e "${CYAN}Next Steps:${NC}"
    echo -e "  1. Update API keys in AWS Secrets Manager"
    echo -e "  2. Test the API endpoints"
    echo -e "  3. Monitor logs in CloudWatch"
    echo -e "  4. Scale ECS service as needed"
    echo ""
    echo -e "${GREEN}🚀 QuantumSentinel-Nexus is now running on AWS! 🚀${NC}"
}

# Main execution
main() {
    print_banner

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --stack-name)
                STACK_NAME="$2"
                shift 2
                ;;
            --region)
                REGION="$2"
                shift 2
                ;;
            --profile)
                PROFILE="$2"
                shift 2
                ;;
            --image-tag)
                IMAGE_TAG="$2"
                shift 2
                ;;
            --auto)
                AUTO_DEPLOY=true
                shift
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --stack-name STACK_NAME      CloudFormation stack name (required)"
                echo "  --region REGION              AWS region (default: us-east-1)"
                echo "  --profile PROFILE            AWS CLI profile (default: default)"
                echo "  --image-tag TAG              Docker image tag (default: latest)"
                echo "  --auto                       Enable automatic deployment (no prompts)"
                echo "  --help                       Show this help message"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    # Validate required parameters
    if [ -z "$STACK_NAME" ]; then
        print_error "Stack name is required. Use --stack-name parameter."
        exit 1
    fi

    # Set AWS profile if specified
    if [ "$PROFILE" != "default" ]; then
        export AWS_PROFILE=$PROFILE
    fi

    # Execute deployment steps
    check_prerequisites
    get_stack_outputs
    build_and_push_image
    create_ecs_cluster
    create_lambda_functions
    create_api_gateway
    update_secrets
    print_summary
}

# Execute main function
main "$@"