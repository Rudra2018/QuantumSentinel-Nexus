#!/bin/bash
# Google Cloud SDK Installation Script for QuantumSentinel-Nexus

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}========================================${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Detect operating system
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
    else
        OS="other"
    fi
    print_info "Detected OS: $OS"
}

# Install Google Cloud SDK on macOS
install_macos() {
    print_header "Installing Google Cloud SDK on macOS"

    # Check if Homebrew is available
    if command -v brew &> /dev/null; then
        print_info "Installing via Homebrew..."
        brew install google-cloud-sdk
        print_success "Google Cloud SDK installed via Homebrew"
    else
        print_info "Homebrew not found. Installing via curl..."

        # Download and install manually
        cd /tmp
        curl -O https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-455.0.0-darwin-x86_64.tar.gz
        tar -xzf google-cloud-cli-455.0.0-darwin-x86_64.tar.gz

        # Install to user directory
        mkdir -p ~/.local
        mv google-cloud-sdk ~/.local/

        # Add to PATH
        echo 'export PATH=$PATH:~/.local/google-cloud-sdk/bin' >> ~/.bash_profile
        echo 'export PATH=$PATH:~/.local/google-cloud-sdk/bin' >> ~/.zshrc

        # Source the path for current session
        export PATH=$PATH:~/.local/google-cloud-sdk/bin

        print_success "Google Cloud SDK installed manually"
        print_warning "Please restart your terminal or run: source ~/.bash_profile"
    fi
}

# Install Google Cloud SDK on Linux
install_linux() {
    print_header "Installing Google Cloud SDK on Linux"

    # Add Google Cloud SDK repository
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list

    # Import Google Cloud public key
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -

    # Install
    sudo apt-get update && sudo apt-get install google-cloud-cli

    print_success "Google Cloud SDK installed via apt"
}

# Install Google Cloud SDK
install_gcloud() {
    detect_os

    case $OS in
        "macos")
            install_macos
            ;;
        "linux")
            install_linux
            ;;
        *)
            print_error "Unsupported operating system"
            print_info "Please install Google Cloud SDK manually from:"
            print_info "https://cloud.google.com/sdk/docs/install"
            exit 1
            ;;
    esac
}

# Verify installation
verify_installation() {
    print_header "Verifying Google Cloud SDK Installation"

    if command -v gcloud &> /dev/null; then
        print_success "Google Cloud SDK is available"
        gcloud version
        return 0
    else
        print_error "Google Cloud SDK not found in PATH"
        print_info "You may need to restart your terminal or add it to PATH manually"
        return 1
    fi
}

# Main installation process
main() {
    print_header "Google Cloud SDK Installation for QuantumSentinel-Nexus"

    # Check if already installed
    if command -v gcloud &> /dev/null; then
        print_success "Google Cloud SDK is already installed"
        gcloud version
        print_info "Skipping installation..."
        exit 0
    fi

    # Install Google Cloud SDK
    install_gcloud

    # Verify installation
    if verify_installation; then
        print_success "Installation completed successfully!"
        print_info "Next steps:"
        print_info "1. Run: gcloud init"
        print_info "2. Run: gcloud auth login"
        print_info "3. Then execute: ./deploy_to_cloud.sh"
    else
        print_error "Installation may have failed"
        print_info "Please try manual installation from: https://cloud.google.com/sdk/docs/install"
    fi
}

main "$@"