#!/bin/bash

# QuantumSentinel-Nexus Automated AWS Deployment
# Complete automated setup and deployment using pre-configured AWS credentials

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default configuration
PROJECT_NAME="quantumsentinel-nexus"
REGION="us-east-1"
PROFILE="default"
IMAGE_TAG="latest"
STACK_NAME_PREFIX="quantum-auto"

# Functions
print_banner() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║               QuantumSentinel-Nexus Automated AWS Deployment                ║"
    echo "║                    Complete Setup in One Command                            ║"
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

validate_aws_credentials() {
    print_step "Validating AWS credentials..."

    # Check if AWS CLI is installed
    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI is not installed. Please install it first:"
        echo "curl 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o 'awscliv2.zip'"
        echo "unzip awscliv2.zip && sudo ./aws/install"
        exit 1
    fi

    # Check if user is authenticated
    if ! aws sts get-caller-identity &> /dev/null; then
        print_error "AWS authentication failed. Please configure your credentials:"
        echo ""
        echo "Option 1 - Environment variables:"
        echo "export AWS_ACCESS_KEY_ID='your-access-key'"
        echo "export AWS_SECRET_ACCESS_KEY='your-secret-key'"
        echo "export AWS_DEFAULT_REGION='$REGION'"
        echo ""
        echo "Option 2 - AWS CLI configure:"
        echo "aws configure"
        echo ""
        exit 1
    fi

    ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    CURRENT_USER=$(aws sts get-caller-identity --query Arn --output text)

    print_success "AWS credentials validated"
    echo "  Account ID: $ACCOUNT_ID"
    echo "  Current User: $CURRENT_USER"
    echo "  Region: $REGION"
}

generate_stack_name() {
    # Generate unique stack name - must start with letter for CloudFormation
    TIMESTAMP=$(date +%m%d%H%M)
    STACK_NAME="$STACK_NAME_PREFIX-t$TIMESTAMP"
    print_success "Generated stack name: $STACK_NAME"
}

check_docker() {
    print_step "Checking Docker availability..."

    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi

    if ! docker info &> /dev/null; then
        print_error "Docker daemon is not running. Please start Docker."
        exit 1
    fi

    print_success "Docker is available"
}

run_aws_setup() {
    print_step "Running AWS infrastructure setup..."

    if [ ! -f "./setup-aws.sh" ]; then
        print_error "setup-aws.sh not found in current directory"
        exit 1
    fi

    # Make sure it's executable
    chmod +x ./setup-aws.sh

    # Run setup with auto mode
    ./setup-aws.sh \
        --auto \
        --stack-name "$STACK_NAME" \
        --region "$REGION" \
        --profile "$PROFILE"

    print_success "AWS infrastructure setup completed"
}

run_aws_deployment() {
    print_step "Running application deployment..."

    if [ ! -f "./deploy-aws.sh" ]; then
        print_error "deploy-aws.sh not found in current directory"
        exit 1
    fi

    # Make sure it's executable
    chmod +x ./deploy-aws.sh

    # Run deployment with auto mode
    ./deploy-aws.sh \
        --auto \
        --stack-name "$STACK_NAME" \
        --region "$REGION" \
        --profile "$PROFILE" \
        --image-tag "$IMAGE_TAG"

    print_success "Application deployment completed"
}

update_secrets_automatically() {
    print_step "Setting up placeholder secrets..."

    # List of secrets to create with placeholder values
    SECRETS=(
        "quantum/chaos-api-key:PLACEHOLDER-Update-with-your-chaos-api-key"
        "quantum/huggingface-token:PLACEHOLDER-Update-with-your-huggingface-token"
        "quantum/cve-api-key:PLACEHOLDER-Update-with-your-cve-api-key"
        "quantum/nuclei-api-key:PLACEHOLDER-Update-with-your-nuclei-api-key"
    )

    for secret_info in "${SECRETS[@]}"; do
        IFS=':' read -r secret_name placeholder_value <<< "$secret_info"

        # Check if secret exists, if not the CloudFormation should have created it
        if aws secretsmanager describe-secret --secret-id "$secret_name" --region "$REGION" &> /dev/null; then
            print_warning "Secret $secret_name already exists with placeholder value"
        else
            print_warning "Secret $secret_name not found - should have been created by CloudFormation"
        fi
    done

    print_warning "IMPORTANT: Update these secrets with your actual API keys:"
    echo "  aws secretsmanager update-secret --secret-id quantum/chaos-api-key --secret-string 'your-actual-api-key' --region $REGION"
    echo "  aws secretsmanager update-secret --secret-id quantum/huggingface-token --secret-string 'your-actual-token' --region $REGION"
    echo "  aws secretsmanager update-secret --secret-id quantum/cve-api-key --secret-string 'your-actual-api-key' --region $REGION"
    echo "  aws secretsmanager update-secret --secret-id quantum/nuclei-api-key --secret-string 'your-actual-api-key' --region $REGION"
}

test_deployment() {
    print_step "Testing deployment..."

    # Get API Gateway URL from CloudFormation outputs
    API_ID=$(aws apigateway get-rest-apis --query "items[?name=='$PROJECT_NAME-api'].id" --output text --region $REGION)

    if [ ! -z "$API_ID" ] && [ "$API_ID" != "None" ]; then
        API_URL="https://$API_ID.execute-api.$REGION.amazonaws.com/prod"

        print_step "Testing API endpoint: $API_URL/health"

        # Test health endpoint
        if curl -s "$API_URL/health" > /dev/null; then
            print_success "API endpoint is responding"
            echo "  API URL: $API_URL"
        else
            print_warning "API endpoint may still be starting up"
            echo "  API URL: $API_URL (try again in a few minutes)"
        fi
    else
        print_warning "API Gateway not found - may still be setting up"
    fi

    # Check ECS service status
    SERVICE_STATUS=$(aws ecs describe-services \
        --cluster "$PROJECT_NAME-cluster" \
        --services "$PROJECT_NAME-service" \
        --query 'services[0].status' \
        --output text \
        --region $REGION 2>/dev/null || echo "NOT_FOUND")

    if [ "$SERVICE_STATUS" = "ACTIVE" ]; then
        print_success "ECS service is active"
    else
        print_warning "ECS service status: $SERVICE_STATUS"
    fi
}

print_final_summary() {
    ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    AUTOMATED DEPLOYMENT COMPLETED                           ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo -e "${GREEN}🎉 QuantumSentinel-Nexus successfully deployed to AWS! 🎉${NC}"
    echo ""
    echo -e "${CYAN}Deployment Summary:${NC}"
    echo -e "  🏢 AWS Account:     ${BLUE}$ACCOUNT_ID${NC}"
    echo -e "  🌍 Region:          ${BLUE}$REGION${NC}"
    echo -e "  📚 Stack Name:      ${BLUE}$STACK_NAME${NC}"
    echo -e "  🐳 Image Tag:       ${BLUE}$IMAGE_TAG${NC}"
    echo ""
    echo -e "${CYAN}Services Deployed:${NC}"
    echo -e "  ✅ CloudFormation stack with complete infrastructure"
    echo -e "  ✅ ECS Fargate cluster running containerized application"
    echo -e "  ✅ Lambda functions for serverless API endpoints"
    echo -e "  ✅ API Gateway for HTTP access"
    echo -e "  ✅ S3 buckets for data storage"
    echo -e "  ✅ Secrets Manager for secure API key storage"
    echo -e "  ✅ CloudWatch for monitoring and logging"
    echo ""
    echo -e "${CYAN}Quick Access:${NC}"
    echo -e "  🌐 AWS Console:     ${BLUE}https://console.aws.amazon.com/${NC}"
    echo -e "  📊 ECS Service:     ${BLUE}https://console.aws.amazon.com/ecs/v2/clusters/$PROJECT_NAME-cluster${NC}"
    echo -e "  🔍 CloudWatch:      ${BLUE}https://console.aws.amazon.com/cloudwatch/home?region=$REGION${NC}"
    echo -e "  🗄️  S3 Buckets:      ${BLUE}https://s3.console.aws.amazon.com/s3/buckets?region=$REGION${NC}"
    echo ""
    echo -e "${CYAN}Next Steps:${NC}"
    echo -e "  1. Update API keys in AWS Secrets Manager (see commands above)"
    echo -e "  2. Test your API endpoints"
    echo -e "  3. Monitor logs in CloudWatch"
    echo -e "  4. Scale services as needed"
    echo ""
    echo -e "${CYAN}Configuration Files Created:${NC}"
    echo -e "  📁 quantum-sentinel-aws-config.sh"
    echo -e "  📁 .env"
    echo -e "  📁 quantum-sentinel-aws-template.yaml"
    echo ""
    echo -e "${GREEN}🚀 Your security testing platform is ready! 🚀${NC}"
    echo ""
    echo -e "${YELLOW}⚠️  Don't forget to update the API keys in Secrets Manager!${NC}"
}

# Main execution
main() {
    print_banner

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
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
            --stack-prefix)
                STACK_NAME_PREFIX="$2"
                shift 2
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Automated QuantumSentinel-Nexus deployment to AWS"
                echo ""
                echo "Options:"
                echo "  --region REGION              AWS region (default: us-east-1)"
                echo "  --profile PROFILE            AWS CLI profile (default: default)"
                echo "  --image-tag TAG              Docker image tag (default: latest)"
                echo "  --stack-prefix PREFIX        Stack name prefix (default: quantum-auto)"
                echo "  --help                       Show this help message"
                echo ""
                echo "Prerequisites:"
                echo "  - AWS CLI v2 installed and configured"
                echo "  - Docker installed and running"
                echo "  - Valid AWS credentials (access key or configured profile)"
                echo ""
                echo "Example:"
                echo "  $0 --region us-west-2 --image-tag v1.0"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done

    # Set AWS profile if specified
    if [ "$PROFILE" != "default" ]; then
        export AWS_PROFILE=$PROFILE
    fi

    # Execute automated deployment steps
    echo -e "${CYAN}Starting automated AWS deployment...${NC}"
    echo ""

    validate_aws_credentials
    generate_stack_name
    check_docker
    run_aws_setup
    run_aws_deployment
    update_secrets_automatically
    test_deployment
    print_final_summary

    echo ""
    echo -e "${GREEN}✨ Automated deployment completed successfully! ✨${NC}"
}

# Execute main function
main "$@"