#!/bin/bash

# QuantumSentinel-Nexus AWS Setup Script
# Automated AWS environment creation, authentication, service enablement, and resource setup

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

# Functions
print_banner() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    QuantumSentinel-Nexus AWS Setup                          ║"
    echo "║                     Amazon Web Services Configuration                       ║"
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
    print_step "Checking prerequisites..."

    # Check if AWS CLI is installed
    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI is not installed."
        echo "Please install it from: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
        exit 1
    fi

    # Check AWS CLI version
    AWS_VERSION=$(aws --version 2>&1 | cut -d/ -f2 | cut -d' ' -f1)
    print_success "AWS CLI version: $AWS_VERSION"

    # Check if user is authenticated
    if ! aws sts get-caller-identity &> /dev/null; then
        print_warning "No active AWS authentication found"
        return 1
    else
        ACTIVE_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
        ACTIVE_USER=$(aws sts get-caller-identity --query Arn --output text)
        print_success "Active account: $ACTIVE_ACCOUNT"
        print_success "Active user: $ACTIVE_USER"
        return 0
    fi
}

authenticate_aws() {
    print_step "Checking AWS authentication..."

    # Check if authentication is already working
    if check_prerequisites; then
        print_success "Using existing AWS authentication"
        return 0
    fi

    # If AUTO_SETUP is enabled, try to use environment variables or configured credentials
    if [ "$AUTO_SETUP" = "true" ]; then
        print_step "Auto-setup mode: checking for configured credentials..."

        # Check for environment variables
        if [ ! -z "$AWS_ACCESS_KEY_ID" ] && [ ! -z "$AWS_SECRET_ACCESS_KEY" ]; then
            print_success "Using AWS credentials from environment variables"
            return 0
        fi

        # Check for configured AWS CLI
        if aws configure list &> /dev/null; then
            print_success "Using AWS CLI configured credentials"
            return 0
        fi

        print_error "Auto-setup mode enabled but no valid credentials found"
        echo "Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables"
        echo "Or run: aws configure"
        exit 1
    fi

    # Interactive mode
    echo -e "${YELLOW}Choose authentication method:${NC}"
    echo "1. AWS SSO (recommended)"
    echo "2. Access key authentication"
    echo "3. Use existing authentication"

    read -p "Enter choice (1-3): " auth_choice

    case $auth_choice in
        1)
            print_step "Setting up AWS SSO..."
            aws configure sso
            ;;
        2)
            print_step "Setting up access key authentication..."
            aws configure
            ;;
        3)
            if check_prerequisites; then
                print_success "Using existing authentication"
            else
                print_error "No valid authentication found"
                exit 1
            fi
            ;;
        *)
            print_error "Invalid choice"
            exit 1
            ;;
    esac

    print_success "AWS authentication completed"
}

create_stack() {
    print_step "Creating AWS CloudFormation stack..."

    # Generate unique stack name if not provided
    if [ -z "$STACK_NAME" ]; then
        TIMESTAMP=$(date +%s)
        RANDOM_SUFFIX=$(shuf -i 1000-9999 -n 1)
        STACK_NAME="$PROJECT_NAME-$RANDOM_SUFFIX"
    fi

    echo -e "${YELLOW}Stack configuration:${NC}"
    echo "  Stack Name: $STACK_NAME"
    echo "  Region: $REGION"

    # Auto-confirm in auto-setup mode
    if [ "$AUTO_SETUP" = "true" ]; then
        print_step "Auto-setup mode: proceeding with stack creation"
    else
        read -p "Proceed with stack creation? (Y/n): " confirm
        if [[ $confirm =~ ^[Nn]$ ]]; then
            read -p "Enter custom stack name: " custom_stack_name
            if [ ! -z "$custom_stack_name" ]; then
                STACK_NAME="$custom_stack_name"
            fi
        fi
    fi

    # Check if stack already exists
    if aws cloudformation describe-stacks --stack-name $STACK_NAME --region $REGION &> /dev/null; then
        print_warning "Stack $STACK_NAME already exists"
        if [ "$AUTO_SETUP" = "true" ]; then
            print_step "Auto-setup mode: using existing stack"
        else
            read -p "Use existing stack? (Y/n): " use_existing
            if [[ $use_existing =~ ^[Nn]$ ]]; then
                print_error "Please choose a different stack name"
                exit 1
            fi
        fi
    else
        # Create the CloudFormation template
        create_cloudformation_template

        # Create the stack
        print_step "Creating stack: $STACK_NAME"
        aws cloudformation create-stack \
            --stack-name $STACK_NAME \
            --template-body file://quantum-sentinel-aws-template.yaml \
            --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
            --region $REGION
        print_success "Stack creation initiated"

        # Wait for stack creation to complete
        print_step "Waiting for stack creation to complete..."
        aws cloudformation wait stack-create-complete \
            --stack-name $STACK_NAME \
            --region $REGION
        print_success "Stack created successfully"
    fi
}

create_cloudformation_template() {
    print_step "Creating CloudFormation template..."

    cat > quantum-sentinel-aws-template.yaml << 'EOF'
AWSTemplateFormatVersion: '2010-09-09'
Description: 'QuantumSentinel-Nexus AWS Infrastructure'

Parameters:
  ProjectName:
    Type: String
    Default: quantumsentinel-nexus
    Description: Name of the project

Resources:
  # S3 Buckets for different purposes
  ReportsBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub '${ProjectName}-quantum-reports-${AWS::AccountId}'
      LifecycleConfiguration:
        Rules:
          - Id: ReportsLifecycle
            Status: Enabled
            ExpirationInDays: 365
      Tags:
        - Key: Project
          Value: !Ref ProjectName
        - Key: Purpose
          Value: reports-and-scan-results

  ResearchDataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub '${ProjectName}-quantum-research-data-${AWS::AccountId}'
      Tags:
        - Key: Project
          Value: !Ref ProjectName
        - Key: Purpose
          Value: research-findings-and-papers

  MLModelsBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub '${ProjectName}-quantum-ml-models-${AWS::AccountId}'
      Tags:
        - Key: Project
          Value: !Ref ProjectName
        - Key: Purpose
          Value: machine-learning-models-and-datasets

  EvidenceBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub '${ProjectName}-quantum-evidence-${AWS::AccountId}'
      LifecycleConfiguration:
        Rules:
          - Id: EvidenceLifecycle
            Status: Enabled
            ExpirationInDays: 730
      Tags:
        - Key: Project
          Value: !Ref ProjectName
        - Key: Purpose
          Value: evidence-files-and-proof-of-concepts

  ConfigsBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub '${ProjectName}-quantum-configs-${AWS::AccountId}'
      Tags:
        - Key: Project
          Value: !Ref ProjectName
        - Key: Purpose
          Value: configuration-files-and-templates

  LogsBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub '${ProjectName}-quantum-logs-${AWS::AccountId}'
      LifecycleConfiguration:
        Rules:
          - Id: LogsLifecycle
            Status: Enabled
            ExpirationInDays: 90
      Tags:
        - Key: Project
          Value: !Ref ProjectName
        - Key: Purpose
          Value: application-logs-and-audit-trails

  # IAM Role for QuantumSentinel services
  QuantumSentinelRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub '${ProjectName}-execution-role'
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service:
                - lambda.amazonaws.com
                - ecs-tasks.amazonaws.com
                - ec2.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
        - arn:aws:iam::aws:policy/AmazonECS_FullAccess
        - arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryFullAccess
      Policies:
        - PolicyName: QuantumSentinelS3Access
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - s3:GetObject
                  - s3:PutObject
                  - s3:DeleteObject
                  - s3:ListBucket
                Resource:
                  - !Sub '${ReportsBucket.Arn}/*'
                  - !Sub '${ResearchDataBucket.Arn}/*'
                  - !Sub '${MLModelsBucket.Arn}/*'
                  - !Sub '${EvidenceBucket.Arn}/*'
                  - !Sub '${ConfigsBucket.Arn}/*'
                  - !Sub '${LogsBucket.Arn}/*'
                  - !GetAtt ReportsBucket.Arn
                  - !GetAtt ResearchDataBucket.Arn
                  - !GetAtt MLModelsBucket.Arn
                  - !GetAtt EvidenceBucket.Arn
                  - !GetAtt ConfigsBucket.Arn
                  - !GetAtt LogsBucket.Arn
        - PolicyName: QuantumSentinelSecretsManagerAccess
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - secretsmanager:GetSecretValue
                  - secretsmanager:DescribeSecret
                Resource: !Sub 'arn:aws:secretsmanager:${AWS::Region}:${AWS::AccountId}:secret:quantum/*'
        - PolicyName: QuantumSentinelCloudWatchAccess
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                  - cloudwatch:PutMetricData
                Resource: '*'

  # Secrets Manager secrets
  ChaosAPIKeySecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Name: quantum/chaos-api-key
      Description: Chaos API key for subdomain enumeration
      SecretString: PLACEHOLDER_VALUE_CHANGE_ME

  HuggingFaceTokenSecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Name: quantum/huggingface-token
      Description: HuggingFace API token for ML models
      SecretString: PLACEHOLDER_VALUE_CHANGE_ME

  CVEAPIKeySecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Name: quantum/cve-api-key
      Description: CVE API key for vulnerability data
      SecretString: PLACEHOLDER_VALUE_CHANGE_ME

  NucleiAPIKeySecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Name: quantum/nuclei-api-key
      Description: Nuclei API key for templates
      SecretString: PLACEHOLDER_VALUE_CHANGE_ME

  DatabasePasswordSecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Name: quantum/database-password
      Description: Database password for RDS
      GenerateSecretString:
        SecretStringTemplate: '{"username": "quantumadmin"}'
        GenerateStringKey: 'password'
        PasswordLength: 32
        ExcludeCharacters: '"@/\'

  RedisPasswordSecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Name: quantum/redis-password
      Description: Redis password for ElastiCache
      GenerateSecretString:
        PasswordLength: 32
        ExcludeCharacters: '"@/\'

  JWTSecretSecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Name: quantum/jwt-secret
      Description: JWT secret for authentication
      GenerateSecretString:
        PasswordLength: 64
        ExcludeCharacters: '"@/\'

  # VPC and Networking
  QuantumVPC:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
      EnableDnsHostnames: true
      EnableDnsSupport: true
      Tags:
        - Key: Name
          Value: !Sub '${ProjectName}-vpc'
        - Key: Project
          Value: !Ref ProjectName

  QuantumSubnetPublic1:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref QuantumVPC
      CidrBlock: 10.0.1.0/24
      AvailabilityZone: !Select [0, !GetAZs '']
      MapPublicIpOnLaunch: true
      Tags:
        - Key: Name
          Value: !Sub '${ProjectName}-public-subnet-1'

  QuantumSubnetPublic2:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref QuantumVPC
      CidrBlock: 10.0.2.0/24
      AvailabilityZone: !Select [1, !GetAZs '']
      MapPublicIpOnLaunch: true
      Tags:
        - Key: Name
          Value: !Sub '${ProjectName}-public-subnet-2'

  QuantumSubnetPrivate1:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref QuantumVPC
      CidrBlock: 10.0.10.0/24
      AvailabilityZone: !Select [0, !GetAZs '']
      Tags:
        - Key: Name
          Value: !Sub '${ProjectName}-private-subnet-1'

  QuantumSubnetPrivate2:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref QuantumVPC
      CidrBlock: 10.0.11.0/24
      AvailabilityZone: !Select [1, !GetAZs '']
      Tags:
        - Key: Name
          Value: !Sub '${ProjectName}-private-subnet-2'

  # Internet Gateway
  QuantumInternetGateway:
    Type: AWS::EC2::InternetGateway
    Properties:
      Tags:
        - Key: Name
          Value: !Sub '${ProjectName}-igw'

  QuantumVPCGatewayAttachment:
    Type: AWS::EC2::VPCGatewayAttachment
    Properties:
      VpcId: !Ref QuantumVPC
      InternetGatewayId: !Ref QuantumInternetGateway

  # Route Tables
  QuantumPublicRouteTable:
    Type: AWS::EC2::RouteTable
    Properties:
      VpcId: !Ref QuantumVPC
      Tags:
        - Key: Name
          Value: !Sub '${ProjectName}-public-rt'

  QuantumPublicRoute:
    Type: AWS::EC2::Route
    DependsOn: QuantumVPCGatewayAttachment
    Properties:
      RouteTableId: !Ref QuantumPublicRouteTable
      DestinationCidrBlock: 0.0.0.0/0
      GatewayId: !Ref QuantumInternetGateway

  QuantumPublicSubnetRouteTableAssociation1:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      SubnetId: !Ref QuantumSubnetPublic1
      RouteTableId: !Ref QuantumPublicRouteTable

  QuantumPublicSubnetRouteTableAssociation2:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      SubnetId: !Ref QuantumSubnetPublic2
      RouteTableId: !Ref QuantumPublicRouteTable

  # Security Groups
  QuantumSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Security group for QuantumSentinel-Nexus
      VpcId: !Ref QuantumVPC
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          CidrIp: 0.0.0.0/0
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 0.0.0.0/0
        - IpProtocol: tcp
          FromPort: 8000
          ToPort: 8080
          CidrIp: 10.0.0.0/16
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 10.0.0.0/16
      Tags:
        - Key: Name
          Value: !Sub '${ProjectName}-sg'

  # ECR Repository
  QuantumECRRepository:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: !Ref ProjectName
      ImageTagMutability: MUTABLE
      LifecyclePolicy:
        LifecyclePolicyText: |
          {
            "rules": [
              {
                "rulePriority": 1,
                "description": "Keep last 10 images",
                "selection": {
                  "tagStatus": "any",
                  "countType": "imageCountMoreThan",
                  "countNumber": 10
                },
                "action": {
                  "type": "expire"
                }
              }
            ]
          }

Outputs:
  StackName:
    Description: Name of the CloudFormation stack
    Value: !Ref AWS::StackName
    Export:
      Name: !Sub '${AWS::StackName}-StackName'

  ReportsBucket:
    Description: S3 bucket for reports
    Value: !Ref ReportsBucket
    Export:
      Name: !Sub '${AWS::StackName}-ReportsBucket'

  ResearchDataBucket:
    Description: S3 bucket for research data
    Value: !Ref ResearchDataBucket
    Export:
      Name: !Sub '${AWS::StackName}-ResearchDataBucket'

  MLModelsBucket:
    Description: S3 bucket for ML models
    Value: !Ref MLModelsBucket
    Export:
      Name: !Sub '${AWS::StackName}-MLModelsBucket'

  EvidenceBucket:
    Description: S3 bucket for evidence
    Value: !Ref EvidenceBucket
    Export:
      Name: !Sub '${AWS::StackName}-EvidenceBucket'

  ConfigsBucket:
    Description: S3 bucket for configs
    Value: !Ref ConfigsBucket
    Export:
      Name: !Sub '${AWS::StackName}-ConfigsBucket'

  LogsBucket:
    Description: S3 bucket for logs
    Value: !Ref LogsBucket
    Export:
      Name: !Sub '${AWS::StackName}-LogsBucket'

  QuantumSentinelRole:
    Description: IAM role for QuantumSentinel services
    Value: !Ref QuantumSentinelRole
    Export:
      Name: !Sub '${AWS::StackName}-QuantumSentinelRole'

  VPCId:
    Description: VPC ID
    Value: !Ref QuantumVPC
    Export:
      Name: !Sub '${AWS::StackName}-VPCId'

  PublicSubnet1Id:
    Description: Public Subnet 1 ID
    Value: !Ref QuantumSubnetPublic1
    Export:
      Name: !Sub '${AWS::StackName}-PublicSubnet1Id'

  PublicSubnet2Id:
    Description: Public Subnet 2 ID
    Value: !Ref QuantumSubnetPublic2
    Export:
      Name: !Sub '${AWS::StackName}-PublicSubnet2Id'

  PrivateSubnet1Id:
    Description: Private Subnet 1 ID
    Value: !Ref QuantumSubnetPrivate1
    Export:
      Name: !Sub '${AWS::StackName}-PrivateSubnet1Id'

  PrivateSubnet2Id:
    Description: Private Subnet 2 ID
    Value: !Ref QuantumSubnetPrivate2
    Export:
      Name: !Sub '${AWS::StackName}-PrivateSubnet2Id'

  SecurityGroupId:
    Description: Security Group ID
    Value: !Ref QuantumSecurityGroup
    Export:
      Name: !Sub '${AWS::StackName}-SecurityGroupId'

  ECRRepository:
    Description: ECR Repository URI
    Value: !Sub '${AWS::AccountId}.dkr.ecr.${AWS::Region}.amazonaws.com/${QuantumECRRepository}'
    Export:
      Name: !Sub '${AWS::StackName}-ECRRepository'
EOF

    print_success "CloudFormation template created"
}

save_configuration() {
    print_step "Saving configuration..."

    # Get stack outputs
    ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

    # Create configuration file
    cat > quantum-sentinel-aws-config.sh << EOF
#!/bin/bash
# QuantumSentinel-Nexus AWS Configuration
export AWS_REGION="$REGION"
export AWS_ACCOUNT_ID="$ACCOUNT_ID"
export CLOUDFORMATION_STACK_NAME="$STACK_NAME"

# S3 Bucket names
export QUANTUM_REPORTS_BUCKET="$PROJECT_NAME-quantum-reports-$ACCOUNT_ID"
export QUANTUM_RESEARCH_DATA_BUCKET="$PROJECT_NAME-quantum-research-data-$ACCOUNT_ID"
export QUANTUM_ML_MODELS_BUCKET="$PROJECT_NAME-quantum-ml-models-$ACCOUNT_ID"
export QUANTUM_EVIDENCE_BUCKET="$PROJECT_NAME-quantum-evidence-$ACCOUNT_ID"
export QUANTUM_CONFIGS_BUCKET="$PROJECT_NAME-quantum-configs-$ACCOUNT_ID"
export QUANTUM_LOGS_BUCKET="$PROJECT_NAME-quantum-logs-$ACCOUNT_ID"

# IAM Role
export QUANTUM_ROLE_ARN="arn:aws:iam::$ACCOUNT_ID:role/$PROJECT_NAME-execution-role"

# ECR Repository
export QUANTUM_ECR_REPOSITORY="$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$PROJECT_NAME"

echo "QuantumSentinel-Nexus AWS configuration loaded for account: $ACCOUNT_ID"
EOF

    chmod +x quantum-sentinel-aws-config.sh

    # Create .env file for Docker
    cat > .env << EOF
# QuantumSentinel-Nexus AWS Environment Variables
AWS_REGION=$REGION
AWS_ACCOUNT_ID=$ACCOUNT_ID
CLOUDFORMATION_STACK_NAME=$STACK_NAME

# S3 Bucket Configuration
QUANTUM_REPORTS_BUCKET=$PROJECT_NAME-quantum-reports-$ACCOUNT_ID
QUANTUM_RESEARCH_DATA_BUCKET=$PROJECT_NAME-quantum-research-data-$ACCOUNT_ID
QUANTUM_ML_MODELS_BUCKET=$PROJECT_NAME-quantum-ml-models-$ACCOUNT_ID
QUANTUM_EVIDENCE_BUCKET=$PROJECT_NAME-quantum-evidence-$ACCOUNT_ID
QUANTUM_CONFIGS_BUCKET=$PROJECT_NAME-quantum-configs-$ACCOUNT_ID
QUANTUM_LOGS_BUCKET=$PROJECT_NAME-quantum-logs-$ACCOUNT_ID

# Service Configuration
QUANTUM_ROLE_ARN=arn:aws:iam::$ACCOUNT_ID:role/$PROJECT_NAME-execution-role
QUANTUM_ECR_REPOSITORY=$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$PROJECT_NAME

# Application Settings
ENVIRONMENT=production
DEBUG=false
LOG_LEVEL=INFO
CLOUD_PROVIDER=aws
EOF

    print_success "Configuration files created:"
    echo "  - quantum-sentinel-aws-config.sh (shell configuration)"
    echo "  - .env (Docker environment variables)"
    echo "  - quantum-sentinel-aws-template.yaml (CloudFormation template)"
}

print_summary() {
    ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                         AWS SETUP COMPLETED                                 ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo -e "${GREEN}QuantumSentinel-Nexus AWS setup completed successfully!${NC}"
    echo ""
    echo -e "${CYAN}AWS Information:${NC}"
    echo -e "  🏢 Account ID:      ${BLUE}$ACCOUNT_ID${NC}"
    echo -e "  🌍 Region:          ${BLUE}$REGION${NC}"
    echo -e "  📚 Stack Name:      ${BLUE}$STACK_NAME${NC}"
    echo ""
    echo -e "${CYAN}Resources Created:${NC}"
    echo -e "  ✅ CloudFormation stack deployed"
    echo -e "  ✅ VPC with public/private subnets"
    echo -e "  ✅ 6 S3 buckets with lifecycle policies"
    echo -e "  ✅ IAM role with appropriate permissions"
    echo -e "  ✅ 7 Secrets Manager secrets"
    echo -e "  ✅ ECR repository for container images"
    echo -e "  ✅ Security groups and networking"
    echo ""
    echo -e "${CYAN}S3 Buckets:${NC}"
    echo -e "  📊 Reports:        ${BLUE}$PROJECT_NAME-quantum-reports-$ACCOUNT_ID${NC}"
    echo -e "  🔬 Research Data:  ${BLUE}$PROJECT_NAME-quantum-research-data-$ACCOUNT_ID${NC}"
    echo -e "  🤖 ML Models:      ${BLUE}$PROJECT_NAME-quantum-ml-models-$ACCOUNT_ID${NC}"
    echo -e "  🔍 Evidence:       ${BLUE}$PROJECT_NAME-quantum-evidence-$ACCOUNT_ID${NC}"
    echo -e "  ⚙️  Configs:        ${BLUE}$PROJECT_NAME-quantum-configs-$ACCOUNT_ID${NC}"
    echo -e "  📝 Logs:           ${BLUE}$PROJECT_NAME-quantum-logs-$ACCOUNT_ID${NC}"
    echo ""
    echo -e "${CYAN}Next Steps:${NC}"
    echo -e "  1. Update API secrets in AWS Secrets Manager:"
    echo -e "     ${YELLOW}aws secretsmanager update-secret --secret-id quantum/chaos-api-key --secret-string 'your-api-key'${NC}"
    echo -e "  2. Load configuration:"
    echo -e "     ${YELLOW}source quantum-sentinel-aws-config.sh${NC}"
    echo -e "  3. Deploy QuantumSentinel-Nexus:"
    echo -e "     ${YELLOW}./deploy-aws.sh --stack-name $STACK_NAME${NC}"
    echo ""
    echo -e "${CYAN}Management URLs:${NC}"
    echo -e "  🖥️  AWS Console:     ${BLUE}https://console.aws.amazon.com/${NC}"
    echo -e "  🗄️  S3 Console:      ${BLUE}https://s3.console.aws.amazon.com/s3/buckets?region=$REGION${NC}"
    echo -e "  🔐 Secrets Manager: ${BLUE}https://console.aws.amazon.com/secretsmanager/home?region=$REGION${NC}"
    echo -e "  📚 CloudFormation:  ${BLUE}https://console.aws.amazon.com/cloudformation/home?region=$REGION#/stacks${NC}"
    echo ""
    echo -e "${GREEN}🚀 Ready to deploy QuantumSentinel-Nexus on AWS! 🚀${NC}"
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
            --auto)
                AUTO_SETUP=true
                shift
                ;;
            --skip-auth)
                SKIP_AUTH=true
                shift
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --stack-name STACK_NAME      Custom CloudFormation stack name"
                echo "  --region REGION              AWS region (default: us-east-1)"
                echo "  --profile PROFILE            AWS CLI profile (default: default)"
                echo "  --auto                       Enable automatic setup mode (no prompts)"
                echo "  --skip-auth                  Skip authentication step"
                echo "  --help                       Show this help message"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    # Set AWS profile if specified
    if [ "$PROFILE" != "default" ]; then
        export AWS_PROFILE=$PROFILE
    fi

    # Execute setup steps
    check_prerequisites || true

    if [ "$SKIP_AUTH" != "true" ]; then
        authenticate_aws
    fi

    create_stack
    save_configuration
    print_summary
}

# Execute main function
main "$@"