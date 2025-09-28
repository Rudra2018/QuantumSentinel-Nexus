#!/bin/bash

# AWS Credentials Configuration Script
# Securely configure AWS credentials for QuantumSentinel-Nexus

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    AWS Credentials Configuration                             ║"
    echo "║                   QuantumSentinel-Nexus Setup                               ║"
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

check_aws_cli() {
    print_step "Checking AWS CLI installation..."

    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI is not installed."
        echo ""
        echo "Please install AWS CLI v2:"
        echo "curl 'https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip' -o 'awscliv2.zip'"
        echo "unzip awscliv2.zip"
        echo "sudo ./aws/install"
        exit 1
    fi

    AWS_VERSION=$(aws --version 2>&1 | cut -d/ -f2 | cut -d' ' -f1)
    print_success "AWS CLI v$AWS_VERSION is installed"
}

configure_credentials() {
    print_step "Configuring AWS credentials..."

    echo ""
    echo -e "${YELLOW}Choose configuration method:${NC}"
    echo "1. Environment variables (recommended for automation)"
    echo "2. AWS CLI configure (interactive)"
    echo "3. AWS SSO (recommended for interactive use)"
    echo "4. Check existing configuration"
    echo ""

    read -p "Enter choice (1-4): " config_choice

    case $config_choice in
        1)
            configure_environment_variables
            ;;
        2)
            configure_aws_cli
            ;;
        3)
            configure_aws_sso
            ;;
        4)
            check_existing_config
            ;;
        *)
            print_error "Invalid choice"
            exit 1
            ;;
    esac
}

configure_environment_variables() {
    print_step "Setting up environment variables..."

    echo ""
    echo -e "${YELLOW}Please provide your AWS credentials:${NC}"
    echo ""

    read -p "AWS Access Key ID: " access_key
    if [ -z "$access_key" ]; then
        print_error "Access Key ID is required"
        exit 1
    fi

    read -s -p "AWS Secret Access Key: " secret_key
    echo ""
    if [ -z "$secret_key" ]; then
        print_error "Secret Access Key is required"
        exit 1
    fi

    read -p "Default Region [us-east-1]: " region
    region=${region:-us-east-1}

    # Create environment configuration file
    cat > aws-credentials.env << EOF
# AWS Credentials for QuantumSentinel-Nexus
# Source this file to set environment variables
export AWS_ACCESS_KEY_ID="$access_key"
export AWS_SECRET_ACCESS_KEY="$secret_key"
export AWS_DEFAULT_REGION="$region"

echo "AWS credentials loaded for region: $region"
EOF

    chmod 600 aws-credentials.env

    print_success "Environment variables configured"
    echo ""
    echo -e "${CYAN}To use these credentials:${NC}"
    echo "  source aws-credentials.env"
    echo ""
    echo -e "${YELLOW}⚠️  Security Note:${NC}"
    echo "  - aws-credentials.env contains sensitive data"
    echo "  - Do not commit this file to version control"
    echo "  - Consider using AWS IAM roles instead for production"
}

configure_aws_cli() {
    print_step "Configuring AWS CLI..."

    echo ""
    echo "Running 'aws configure' - you'll be prompted for credentials:"
    aws configure

    print_success "AWS CLI configured"
}

configure_aws_sso() {
    print_step "Configuring AWS SSO..."

    echo ""
    echo "Running 'aws configure sso' - follow the browser prompts:"
    aws configure sso

    print_success "AWS SSO configured"
}

check_existing_config() {
    print_step "Checking existing AWS configuration..."

    # Check if credentials are available
    if aws sts get-caller-identity &> /dev/null; then
        ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
        USER_ARN=$(aws sts get-caller-identity --query Arn --output text)
        REGION=$(aws configure get region || echo "not-configured")

        print_success "AWS credentials are working"
        echo "  Account ID: $ACCOUNT_ID"
        echo "  User/Role: $USER_ARN"
        echo "  Region: $REGION"
    else
        print_warning "No working AWS credentials found"
        echo ""
        echo "Please configure credentials using one of the other options"
    fi

    # Show configuration sources
    echo ""
    echo -e "${CYAN}Configuration sources:${NC}"
    aws configure list
}

test_credentials() {
    print_step "Testing AWS credentials..."

    if aws sts get-caller-identity &> /dev/null; then
        ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
        print_success "Credentials are working"
        echo "  Account ID: $ACCOUNT_ID"

        # Test basic permissions
        print_step "Testing basic AWS permissions..."

        # Test S3 access
        if aws s3 ls &> /dev/null; then
            print_success "S3 access confirmed"
        else
            print_warning "S3 access denied - may need additional permissions"
        fi

        # Test CloudFormation access
        if aws cloudformation list-stacks --max-items 1 &> /dev/null; then
            print_success "CloudFormation access confirmed"
        else
            print_warning "CloudFormation access denied - may need additional permissions"
        fi

        # Test ECS access
        if aws ecs list-clusters --max-items 1 &> /dev/null; then
            print_success "ECS access confirmed"
        else
            print_warning "ECS access denied - may need additional permissions"
        fi

    else
        print_error "Credentials test failed"
        echo "Please reconfigure your AWS credentials"
        exit 1
    fi
}

create_launch_script() {
    print_step "Creating quick launch script..."

    cat > quick-deploy.sh << 'EOF'
#!/bin/bash

# QuantumSentinel-Nexus Quick Deploy
# Load credentials and run automated deployment

set -e

echo "🚀 QuantumSentinel-Nexus Quick Deploy"
echo ""

# Check if credentials file exists
if [ -f "aws-credentials.env" ]; then
    echo "Loading AWS credentials from aws-credentials.env..."
    source aws-credentials.env
    echo ""
fi

# Check if credentials are working
if ! aws sts get-caller-identity &> /dev/null; then
    echo "❌ AWS credentials not found or invalid"
    echo "Please run: ./configure-aws-credentials.sh"
    exit 1
fi

echo "✅ AWS credentials verified"
echo ""

# Run automated deployment
if [ -f "auto-deploy-aws.sh" ]; then
    echo "Starting automated deployment..."
    ./auto-deploy-aws.sh "$@"
else
    echo "❌ auto-deploy-aws.sh not found"
    exit 1
fi
EOF

    chmod +x quick-deploy.sh

    print_success "Quick launch script created: quick-deploy.sh"
}

print_summary() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                        CONFIGURATION COMPLETED                              ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    print_success "AWS credentials configuration completed!"
    echo ""
    echo -e "${CYAN}Next steps:${NC}"
    echo ""
    echo -e "${YELLOW}Option 1 - Full automated deployment:${NC}"
    echo "  ./auto-deploy-aws.sh"
    echo ""
    echo -e "${YELLOW}Option 2 - Quick deploy (if you used environment variables):${NC}"
    echo "  ./quick-deploy.sh"
    echo ""
    echo -e "${YELLOW}Option 3 - Manual step-by-step:${NC}"
    echo "  ./setup-aws.sh --auto"
    echo "  ./deploy-aws.sh --auto --stack-name YOUR_STACK_NAME"
    echo ""
    echo -e "${CYAN}Files created:${NC}"
    if [ -f "aws-credentials.env" ]; then
        echo "  📁 aws-credentials.env (credentials file - keep secure!)"
    fi
    echo "  📁 quick-deploy.sh (quick deployment script)"
    echo ""
    echo -e "${GREEN}🚀 Ready to deploy QuantumSentinel-Nexus to AWS! 🚀${NC}"
}

# Main execution
main() {
    print_banner

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --test-only)
                check_aws_cli
                test_credentials
                exit 0
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Configure AWS credentials for QuantumSentinel-Nexus deployment"
                echo ""
                echo "Options:"
                echo "  --test-only                  Only test existing credentials"
                echo "  --help                       Show this help message"
                echo ""
                echo "This script helps you configure AWS credentials securely for"
                echo "automated deployment of QuantumSentinel-Nexus to AWS."
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done

    # Execute configuration steps
    check_aws_cli
    configure_credentials
    test_credentials
    create_launch_script
    print_summary
}

# Execute main function
main "$@"