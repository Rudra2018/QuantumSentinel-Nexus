# QuantumSentinel-Nexus AWS Quick Start Guide

## Overview

This guide will help you quickly deploy QuantumSentinel-Nexus on Amazon Web Services (AWS) using modern cloud-native services including ECS Fargate, Lambda, API Gateway, and more.

## Prerequisites

Before starting, ensure you have:

1. **AWS Account** with appropriate permissions
2. **AWS CLI v2** installed and configured
3. **Docker** installed for container builds
4. **jq** for JSON processing (optional but recommended)

## Quick Setup

### Step 1: Install and Configure AWS CLI

```bash
# Install AWS CLI v2 (if not already installed)
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Configure AWS credentials
aws configure
# OR use AWS SSO
aws configure sso
```

### Step 2: Set Up AWS Infrastructure

Run the AWS setup script to create all necessary infrastructure:

```bash
# Make the setup script executable
chmod +x setup-aws.sh

# Run the setup with default options
./setup-aws.sh

# Or customize the setup
./setup-aws.sh --region us-west-2 --stack-name my-quantum-stack
```

This script will create:
- ✅ CloudFormation stack with all resources
- ✅ VPC with public/private subnets
- ✅ 6 S3 buckets for different data types
- ✅ IAM roles and policies
- ✅ Secrets Manager secrets
- ✅ ECR repository for Docker images
- ✅ Security groups and networking

### Step 3: Load Configuration

After setup completes, load the AWS configuration:

```bash
# Load the generated configuration
source quantum-sentinel-aws-config.sh

# Verify configuration
echo "AWS Account: $AWS_ACCOUNT_ID"
echo "Region: $AWS_REGION"
echo "Stack: $CLOUDFORMATION_STACK_NAME"
```

### Step 4: Deploy the Application

Deploy QuantumSentinel-Nexus to AWS:

```bash
# Make the deployment script executable
chmod +x deploy-aws.sh

# Deploy using the stack name from setup
./deploy-aws.sh --stack-name $CLOUDFORMATION_STACK_NAME

# Or specify parameters explicitly
./deploy-aws.sh --stack-name my-quantum-stack --region us-east-1
```

This will:
- 🐳 Build and push Docker image to ECR
- ⚡ Create ECS Fargate cluster and service
- 🔧 Deploy Lambda functions for API endpoints
- 🌐 Set up API Gateway for HTTP access
- 📊 Configure CloudWatch logging

### Step 5: Update API Keys

Update the placeholder secrets with your actual API keys:

```bash
# Update Chaos API key
aws secretsmanager update-secret \
    --secret-id quantum/chaos-api-key \
    --secret-string 'your-actual-chaos-api-key'

# Update HuggingFace token
aws secretsmanager update-secret \
    --secret-id quantum/huggingface-token \
    --secret-string 'your-huggingface-token'

# Update other API keys as needed
aws secretsmanager update-secret \
    --secret-id quantum/cve-api-key \
    --secret-string 'your-cve-api-key'
```

## Service Architecture

### AWS Services Used

| Service | Purpose | Notes |
|---------|---------|--------|
| **ECS Fargate** | Container hosting | Main application runtime |
| **Lambda** | Serverless APIs | REST API endpoints |
| **API Gateway** | HTTP routing | Public API access |
| **S3** | Object storage | Reports, data, logs |
| **Secrets Manager** | API key storage | Secure credential management |
| **ECR** | Container registry | Docker image storage |
| **CloudWatch** | Monitoring/logging | Application observability |
| **VPC** | Networking | Secure network isolation |

### Storage Buckets

The following S3 buckets are created automatically:

```bash
# Generated bucket names (replace ACCOUNT_ID with your AWS account ID)
quantumsentinel-nexus-quantum-reports-ACCOUNT_ID          # Scan reports
quantumsentinel-nexus-quantum-research-data-ACCOUNT_ID    # Research findings
quantumsentinel-nexus-quantum-ml-models-ACCOUNT_ID        # ML models
quantumsentinel-nexus-quantum-evidence-ACCOUNT_ID         # Evidence files
quantumsentinel-nexus-quantum-configs-ACCOUNT_ID          # Configurations
quantumsentinel-nexus-quantum-logs-ACCOUNT_ID             # Application logs
```

## Usage Examples

### 1. Health Check

Test the deployed API:

```bash
# Get your API Gateway URL from deployment output
API_URL="https://YOUR-API-ID.execute-api.us-east-1.amazonaws.com/prod"

# Test health endpoint
curl $API_URL/health
```

### 2. Start a Security Scan

```bash
# Submit a scan request
curl -X POST $API_URL/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "scan_type": "web"
  }'
```

### 3. Monitor ECS Service

```bash
# Check ECS service status
aws ecs describe-services \
  --cluster quantumsentinel-nexus-cluster \
  --services quantumsentinel-nexus-service

# View ECS task logs
aws logs tail /ecs/quantumsentinel-nexus --follow
```

### 4. Access S3 Data

```bash
# List scan reports
aws s3 ls s3://quantumsentinel-nexus-quantum-reports-$AWS_ACCOUNT_ID/

# Download a specific report
aws s3 cp s3://quantumsentinel-nexus-quantum-reports-$AWS_ACCOUNT_ID/report.json ./
```

## Management Commands

### Scale ECS Service

```bash
# Scale up to 3 instances
aws ecs update-service \
  --cluster quantumsentinel-nexus-cluster \
  --service quantumsentinel-nexus-service \
  --desired-count 3
```

### Update Application

```bash
# Rebuild and redeploy
./deploy-aws.sh --stack-name $CLOUDFORMATION_STACK_NAME --image-tag v2.0
```

### View Logs

```bash
# Application logs
aws logs tail /ecs/quantumsentinel-nexus --follow

# Lambda logs
aws logs tail /aws/lambda/quantumsentinel-nexus-api --follow
```

## Cleanup

To remove all AWS resources:

```bash
# Delete ECS service
aws ecs update-service \
  --cluster quantumsentinel-nexus-cluster \
  --service quantumsentinel-nexus-service \
  --desired-count 0

aws ecs delete-service \
  --cluster quantumsentinel-nexus-cluster \
  --service quantumsentinel-nexus-service

# Delete CloudFormation stack (this removes most resources)
aws cloudformation delete-stack \
  --stack-name $CLOUDFORMATION_STACK_NAME

# Clean up ECR repository
aws ecr delete-repository \
  --repository-name quantumsentinel-nexus \
  --force
```

## Troubleshooting

### Common Issues

1. **Authentication Errors**
   ```bash
   # Verify AWS credentials
   aws sts get-caller-identity

   # Re-configure if needed
   aws configure
   ```

2. **ECS Task Failures**
   ```bash
   # Check task definition
   aws ecs describe-task-definition --task-definition quantumsentinel-nexus-task

   # View task logs
   aws logs describe-log-groups --log-group-name-prefix "/ecs/"
   ```

3. **API Gateway Issues**
   ```bash
   # List API Gateways
   aws apigateway get-rest-apis

   # Check Lambda function
   aws lambda get-function --function-name quantumsentinel-nexus-api
   ```

### Getting Help

- 📚 [AWS ECS Documentation](https://docs.aws.amazon.com/ecs/)
- 🔧 [AWS Lambda Documentation](https://docs.aws.amazon.com/lambda/)
- 🌐 [API Gateway Documentation](https://docs.aws.amazon.com/apigateway/)
- 💬 [QuantumSentinel-Nexus Issues](https://github.com/your-repo/issues)

## Security Best Practices

1. **IAM Permissions**: Use least-privilege access
2. **Secrets Management**: Store all API keys in Secrets Manager
3. **VPC Security**: Use private subnets for sensitive resources
4. **Logging**: Enable CloudTrail for audit logging
5. **Encryption**: Enable S3 encryption and ECS encryption in transit

---

🚀 **You're now ready to use QuantumSentinel-Nexus on AWS!**

The platform is deployed using AWS best practices with automatic scaling, monitoring, and security features. Your security testing infrastructure is ready for production workloads.