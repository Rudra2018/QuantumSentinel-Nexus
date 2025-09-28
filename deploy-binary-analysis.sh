#!/bin/bash
# Binary Analysis Service Deployment Script for QuantumSentinel-Nexus

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
REGION="us-east-1"
CLUSTER_NAME="quantumsentinel-nexus-cluster"
SERVICE_NAME="quantumsentinel-binary-analysis"
ECR_REPO="quantumsentinel-binary-analysis"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

echo -e "${PURPLE}"
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║              BINARY ANALYSIS SERVICE DEPLOYMENT                             ║"
echo "║                    QuantumSentinel-Nexus v6.0                               ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running from correct directory
if [ ! -f "services/binary-analysis/main.py" ]; then
    print_error "Please run this script from the QuantumSentinel-Nexus root directory"
    exit 1
fi

print_info "Starting Binary Analysis Service deployment..."

# 1. Create ECR repository if it doesn't exist
print_info "Setting up ECR repository..."
aws ecr describe-repositories --repository-names $ECR_REPO --region $REGION 2>/dev/null || {
    print_info "Creating ECR repository: $ECR_REPO"
    aws ecr create-repository --repository-name $ECR_REPO --region $REGION
}

# 2. Get ECR login
print_info "Logging into ECR..."
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com

# 3. Build Docker image
print_info "Building Docker image for Binary Analysis service..."
cd services/binary-analysis

# Copy required files
cp ../../ai_agents/binary_analysis_agent.py ./

# Build the image
docker build -t $ECR_REPO:latest .

# Tag for ECR
docker tag $ECR_REPO:latest $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$ECR_REPO:latest

# 4. Push to ECR
print_info "Pushing image to ECR..."
docker push $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$ECR_REPO:latest

cd ../..

# 5. Register task definition
print_info "Registering ECS task definition..."
aws ecs register-task-definition \
    --cli-input-json file://binary-analysis-task-def.json \
    --region $REGION

# 6. Create or update ECS service
print_info "Creating/updating ECS service..."

# Check if service exists
SERVICE_EXISTS=$(aws ecs describe-services \
    --cluster $CLUSTER_NAME \
    --services $SERVICE_NAME \
    --region $REGION \
    --query 'services' \
    --output text 2>/dev/null || echo "")

if [ -n "$SERVICE_EXISTS" ]; then
    print_info "Updating existing service..."
    aws ecs update-service \
        --cluster $CLUSTER_NAME \
        --service $SERVICE_NAME \
        --task-definition $SERVICE_NAME \
        --desired-count 1 \
        --region $REGION
else
    print_info "Creating new service..."

    # Get subnet IDs from existing services
    SUBNET_IDS=$(aws ecs describe-services \
        --cluster $CLUSTER_NAME \
        --services quantumsentinel-ibb-research \
        --region $REGION \
        --query 'services[0].networkConfiguration.awsvpcConfiguration.subnets' \
        --output text 2>/dev/null || echo "")

    # Get security group IDs
    SECURITY_GROUP_IDS=$(aws ecs describe-services \
        --cluster $CLUSTER_NAME \
        --services quantumsentinel-ibb-research \
        --region $REGION \
        --query 'services[0].networkConfiguration.awsvpcConfiguration.securityGroups' \
        --output text 2>/dev/null || echo "")

    if [ -n "$SUBNET_IDS" ] && [ -n "$SECURITY_GROUP_IDS" ]; then
        aws ecs create-service \
            --cluster $CLUSTER_NAME \
            --service-name $SERVICE_NAME \
            --task-definition $SERVICE_NAME \
            --desired-count 1 \
            --launch-type FARGATE \
            --network-configuration "awsvpcConfiguration={subnets=[$SUBNET_IDS],securityGroups=[$SECURITY_GROUP_IDS],assignPublicIp=ENABLED}" \
            --region $REGION
    else
        print_error "Could not find network configuration from existing services"
        exit 1
    fi
fi

# 7. Wait for service to stabilize
print_info "Waiting for service to stabilize..."
aws ecs wait services-stable \
    --cluster $CLUSTER_NAME \
    --services $SERVICE_NAME \
    --region $REGION

# 8. Get service status and IP
print_info "Getting service information..."

TASK_ARN=$(aws ecs list-tasks \
    --cluster $CLUSTER_NAME \
    --service-name $SERVICE_NAME \
    --region $REGION \
    --query 'taskArns[0]' \
    --output text)

if [ "$TASK_ARN" != "None" ] && [ -n "$TASK_ARN" ]; then
    # Get network interface ID
    ENI_ID=$(aws ecs describe-tasks \
        --cluster $CLUSTER_NAME \
        --tasks $TASK_ARN \
        --region $REGION \
        --query 'tasks[0].attachments[0].details[?name==`networkInterfaceId`].value' \
        --output text)

    if [ -n "$ENI_ID" ]; then
        # Get public IP
        PUBLIC_IP=$(aws ec2 describe-network-interfaces \
            --network-interface-ids $ENI_ID \
            --region $REGION \
            --query 'NetworkInterfaces[0].Association.PublicIp' \
            --output text)

        if [ "$PUBLIC_IP" != "None" ] && [ -n "$PUBLIC_IP" ]; then
            print_success "Binary Analysis service deployed successfully!"
            print_info "Public IP: $PUBLIC_IP"
            print_info "Service URL: http://$PUBLIC_IP:8008"

            # Test health endpoint
            print_info "Testing health endpoint..."
            sleep 30  # Wait for service to start

            if curl -f -s "http://$PUBLIC_IP:8008/health" > /dev/null; then
                print_success "Health check passed!"

                # Display service info
                echo -e "\n${CYAN}Service Information:${NC}"
                curl -s "http://$PUBLIC_IP:8008/health" | python3 -m json.tool

            else
                print_warning "Health check failed - service may still be starting"
            fi

            # Update service IPs file
            print_info "Updating service IPs configuration..."
            sed -i.bak "s/quantumsentinel-binary-analysis: .*/quantumsentinel-binary-analysis: $PUBLIC_IP/" services/ibb-research/service_ips.txt

        fi
    fi
fi

echo -e "\n${GREEN}✅ Binary Analysis Service deployment completed!${NC}"
echo -e "${CYAN}Next steps:${NC}"
echo -e "  1. Service is now integrated with the comprehensive bounty engine"
echo -e "  2. Binary analysis will be performed for relevant programs"
echo -e "  3. Check CloudWatch logs for service activity"
echo -e "  4. Monitor service health at http://$PUBLIC_IP:8008/health"

echo -e "\n${PURPLE}🔬 Binary Analysis Service is now operational! 🔬${NC}"