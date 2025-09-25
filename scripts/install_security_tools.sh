#!/bin/bash
# QuantumSentinel-Nexus Security Tools Installation Script
# Installs Go-based security tools for comprehensive assessment

set -e

echo "🛡️ Installing QuantumSentinel-Nexus Security Tools"
echo "================================================="

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go 1.19+ first."
    exit 1
fi

# Create tools directory
mkdir -p tools
cd tools

echo "📦 Installing Go-based security tools..."

# Subfinder
echo "Installing Subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Httpx
echo "Installing Httpx..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Nuclei
echo "Installing Nuclei..."
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Katana
echo "Installing Katana..."
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# Naabu
echo "Installing Naabu..."
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# FFUF
echo "Installing FFUF..."
go install github.com/ffuf/ffuf@latest

# Amass
echo "Installing Amass..."
go install -v github.com/owasp-amass/amass/v4/...@master

echo "✅ Go-based tools installed successfully!"

# Update Nuclei templates
echo "📋 Updating Nuclei templates..."
nuclei -update-templates || true

echo "🎯 Installation complete!"
echo "All security tools are ready for QuantumSentinel-Nexus v3.0"