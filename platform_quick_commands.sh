#!/bin/bash
# QuantumSentinel-Nexus Platform Quick Commands
# One-liner commands for all major bug bounty platforms

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
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

# Function to check if target is provided
check_target() {
    if [ -z "$1" ]; then
        print_error "Target URL/file required!"
        echo "Usage: $0 <command> <target>"
        exit 1
    fi
}

# =============================================================================
# HACKERONE COMMANDS
# =============================================================================

hackerone_web() {
    check_target "$1"
    print_header "HackerOne Web Application Test"
    print_info "Target: $1"
    print_info "Expected bounty: \$1,000 - \$50,000+"

    python3 run_multi_platform_bounty.py \
        --platform hackerone \
        --target "$1" \
        --type web_application \
        --output-dir "./results/hackerone"
}

hackerone_mobile() {
    check_target "$1"
    print_header "HackerOne Mobile Application Test"
    print_info "Target: $1"
    print_info "Expected bounty: \$500 - \$25,000+"

    python3 run_multi_platform_bounty.py \
        --platform hackerone \
        --target "$1" \
        --type mobile_application \
        --output-dir "./results/hackerone"
}

hackerone_api() {
    check_target "$1"
    print_header "HackerOne API Security Test"
    print_info "Target: $1"
    print_info "Expected bounty: \$1,000 - \$20,000+"

    python3 run_multi_platform_bounty.py \
        --platform hackerone \
        --target "$1" \
        --type api \
        --output-dir "./results/hackerone"
}

# =============================================================================
# BUGCROWD COMMANDS
# =============================================================================

bugcrowd_comprehensive() {
    check_target "$1"
    print_header "Bugcrowd Comprehensive Security Test"
    print_info "Target: $1"
    print_info "Expected bounty: \$500 - \$25,000+"

    python3 run_multi_platform_bounty.py \
        --platform bugcrowd \
        --target "$1" \
        --type web_application \
        --output-dir "./results/bugcrowd"
}

bugcrowd_infrastructure() {
    check_target "$1"
    print_header "Bugcrowd Infrastructure Test"
    print_info "Target: $1"
    print_info "Expected bounty: \$1,000 - \$15,000+"

    python3 run_multi_platform_bounty.py \
        --platform bugcrowd \
        --target "$1" \
        --type infrastructure \
        --output-dir "./results/bugcrowd"
}

# =============================================================================
# GOOGLE VRP COMMANDS
# =============================================================================

google_web() {
    check_target "$1"
    print_header "Google VRP Web Application Test"
    print_info "Target: $1"
    print_info "Expected bounty: \$3,133 - \$31,337+"

    python3 run_multi_platform_bounty.py \
        --platform google_vrp \
        --target "$1" \
        --type web_application \
        --output-dir "./results/google_vrp"
}

google_android() {
    check_target "$1"
    print_header "Google VRP Android Application Test"
    print_info "Target: $1"
    print_info "Expected bounty: \$1,337 - \$31,337+"

    python3 run_multi_platform_bounty.py \
        --platform google_vrp \
        --target "$1" \
        --type mobile_application \
        --output-dir "./results/google_vrp"
}

google_api() {
    check_target "$1"
    print_header "Google VRP API Security Test"
    print_info "Target: $1"
    print_info "Expected bounty: \$5,000 - \$31,337+"

    python3 run_multi_platform_bounty.py \
        --platform google_vrp \
        --target "$1" \
        --type api \
        --output-dir "./results/google_vrp"
}

# =============================================================================
# APPLE SECURITY COMMANDS
# =============================================================================

apple_ios() {
    check_target "$1"
    print_header "Apple Security iOS Application Test"
    print_warning "Invitation-only program!"
    print_info "Target: $1"
    print_info "Expected bounty: \$25,000 - \$1,000,000+"

    python3 run_multi_platform_bounty.py \
        --platform apple_security \
        --target "$1" \
        --type mobile_application \
        --output-dir "./results/apple_security"
}

apple_macos() {
    check_target "$1"
    print_header "Apple Security macOS Application Test"
    print_warning "Invitation-only program!"
    print_info "Target: $1"
    print_info "Expected bounty: \$5,000 - \$500,000+"

    python3 run_multi_platform_bounty.py \
        --platform apple_security \
        --target "$1" \
        --type infrastructure \
        --output-dir "./results/apple_security"
}

# =============================================================================
# MICROSOFT MSRC COMMANDS
# =============================================================================

microsoft_azure() {
    check_target "$1"
    print_header "Microsoft MSRC Azure Security Test"
    print_info "Target: $1"
    print_info "Expected bounty: \$15,000 - \$40,000+"

    python3 run_multi_platform_bounty.py \
        --platform microsoft_msrc \
        --target "$1" \
        --type web_application \
        --output-dir "./results/microsoft_msrc"
}

microsoft_windows() {
    check_target "$1"
    print_header "Microsoft MSRC Windows Security Test"
    print_info "Target: $1"
    print_info "Expected bounty: \$15,000 - \$250,000+"

    python3 run_multi_platform_bounty.py \
        --platform microsoft_msrc \
        --target "$1" \
        --type infrastructure \
        --output-dir "./results/microsoft_msrc"
}

# =============================================================================
# SAMSUNG MOBILE COMMANDS
# =============================================================================

samsung_device() {
    check_target "$1"
    print_header "Samsung Mobile Security Test"
    print_info "Target: $1"
    print_info "Expected bounty: \$5,000 - \$200,000+"

    python3 run_multi_platform_bounty.py \
        --platform samsung_mobile \
        --target "$1" \
        --type mobile_application \
        --output-dir "./results/samsung_mobile"
}

# =============================================================================
# INTIGRITI COMMANDS
# =============================================================================

intigriti_gdpr() {
    check_target "$1"
    print_header "Intigriti GDPR Compliance Test"
    print_info "Target: $1"
    print_info "Expected bounty: \$500 - \$15,000+"

    python3 run_multi_platform_bounty.py \
        --platform intigriti \
        --target "$1" \
        --type web_application \
        --output-dir "./results/intigriti"
}

# =============================================================================
# MULTI-PLATFORM COMMANDS
# =============================================================================

test_all_platforms() {
    check_target "$1"
    print_header "Multi-Platform Comprehensive Test"
    print_info "Target: $1"
    print_info "Testing on ALL platforms..."

    python3 run_multi_platform_bounty.py \
        --platform hackerone,bugcrowd,google_vrp,intigriti \
        --target "$1" \
        --type auto \
        --output-dir "./results/multi_platform"
}

test_vendor_programs() {
    check_target "$1"
    print_header "Vendor Programs Test (Google, Apple, Microsoft)"
    print_info "Target: $1"
    print_info "Highest bounty potential!"

    python3 run_multi_platform_bounty.py \
        --platform google_vrp,apple_security,microsoft_msrc \
        --target "$1" \
        --type auto \
        --output-dir "./results/vendor_programs"
}

test_crowd_platforms() {
    check_target "$1"
    print_header "Crowd Platforms Test (HackerOne, Bugcrowd, Intigriti)"
    print_info "Target: $1"
    print_info "Best for beginners and volume!"

    python3 run_multi_platform_bounty.py \
        --platform hackerone,bugcrowd,intigriti \
        --target "$1" \
        --type auto \
        --output-dir "./results/crowd_platforms"
}

# =============================================================================
# HIGH-VALUE QUICK TARGETS
# =============================================================================

target_shopify() {
    print_header "Shopify HackerOne Program"
    print_info "One of the highest-paying programs"
    print_info "Focus: E-commerce, payment, business logic"
    hackerone_web "https://shopify.com"
}

target_uber() {
    print_header "Uber HackerOne Program"
    print_info "High-volume, good payouts"
    print_info "Focus: Mobile apps, APIs, location services"
    hackerone_web "https://uber.com"
}

target_google_search() {
    print_header "Google Search VRP"
    print_info "Core Google service"
    print_info "Focus: Search algorithms, authentication"
    google_web "https://google.com"
}

target_microsoft_azure() {
    print_header "Microsoft Azure Security"
    print_info "High-value cloud platform"
    print_info "Focus: Cloud misconfigurations, identity"
    microsoft_azure "https://portal.azure.com"
}

# =============================================================================
# CHAOS PROJECTDISCOVERY INTEGRATION
# =============================================================================

chaos_multi_program() {
    print_header "Chaos ProjectDiscovery Multi-Program Assessment"
    print_info "Fetching and testing programs from Chaos API..."
    print_info "API Key configured for automated discovery"

    python3 chaos_integration.py
}

chaos_discover_domains() {
    check_target "$1"
    print_header "Chaos Domain Discovery"
    print_info "Program: $1"
    print_info "Discovering domains via Chaos API..."

    python3 -c "
from chaos_integration import ChaosIntegration
chaos = ChaosIntegration('1545c524-7e20-4b62-aa4a-8235255cff96')
domains = chaos.fetch_domains_for_program('$1')
print(f'Found {len(domains)} domains for $1')
for domain in domains[:10]:
    print(f'  • {domain}')
"
}

hackerone_mobile_comprehensive() {
    print_header "HackerOne Mobile Applications Comprehensive Scan"
    print_info "Scanning ALL HackerOne programs for mobile vulnerabilities"
    print_info "Target: Android & iOS applications"
    print_info "Expected findings: Authentication, data storage, network security"

    python3 hackerone_mobile_scanner.py
}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

list_platforms() {
    print_header "Supported Bug Bounty Platforms"

    echo -e "${YELLOW}🔵 HackerOne${NC}"
    echo "   • hackerone_web <target>     - Web application test"
    echo "   • hackerone_mobile <target>  - Mobile application test"
    echo "   • hackerone_api <target>     - API security test"
    echo ""

    echo -e "${YELLOW}🟠 Bugcrowd${NC}"
    echo "   • bugcrowd_comprehensive <target>  - Full security test"
    echo "   • bugcrowd_infrastructure <target> - Infrastructure test"
    echo ""

    echo -e "${YELLOW}🔴 Google VRP${NC}"
    echo "   • google_web <target>        - Google web services"
    echo "   • google_android <target>    - Android application"
    echo "   • google_api <target>        - Google API test"
    echo ""

    echo -e "${YELLOW}🍎 Apple Security${NC}"
    echo "   • apple_ios <target>         - iOS application (invitation only)"
    echo "   • apple_macos <target>       - macOS application (invitation only)"
    echo ""

    echo -e "${YELLOW}🔵 Microsoft MSRC${NC}"
    echo "   • microsoft_azure <target>   - Azure security test"
    echo "   • microsoft_windows <target> - Windows security test"
    echo ""

    echo -e "${YELLOW}📱 Samsung Mobile${NC}"
    echo "   • samsung_device <target>    - Samsung device security"
    echo ""

    echo -e "${YELLOW}🟡 Intigriti${NC}"
    echo "   • intigriti_gdpr <target>    - GDPR compliance test"
    echo ""

    echo -e "${YELLOW}🚀 Multi-Platform${NC}"
    echo "   • test_all_platforms <target>    - Test on all platforms"
    echo "   • test_vendor_programs <target>  - Google, Apple, Microsoft"
    echo "   • test_crowd_platforms <target>  - HackerOne, Bugcrowd, Intigriti"
    echo ""

    echo -e "${YELLOW}🎯 Quick Targets${NC}"
    echo "   • target_shopify             - Shopify HackerOne"
    echo "   • target_uber                - Uber HackerOne"
    echo "   • target_google_search       - Google Search VRP"
    echo "   • target_microsoft_azure     - Microsoft Azure"
    echo ""

    echo -e "${YELLOW}🌪️ Chaos ProjectDiscovery${NC}"
    echo "   • chaos_multi_program        - Auto-discover and test multiple programs"
    echo "   • chaos_discover_domains <program> - Discover domains for specific program"
    echo ""

    echo -e "${YELLOW}📱 HackerOne Mobile Security${NC}"
    echo "   • hackerone_mobile_comprehensive - Comprehensive mobile app scan (ALL programs)"
}

show_bounty_ranges() {
    print_header "Platform Bounty Ranges"

    echo -e "${GREEN}💰 Highest Bounty Potential:${NC}"
    echo "   🍎 Apple Security:    \$5,000 - \$1,000,000+"
    echo "   🔵 Microsoft MSRC:    \$500 - \$250,000"
    echo "   🔴 Google VRP:        \$100 - \$31,337+"
    echo "   🔵 HackerOne:         \$100 - \$50,000+"
    echo "   🟠 Bugcrowd:          \$50 - \$25,000+"
    echo "   📱 Samsung Mobile:    \$100 - \$200,000"
    echo "   🟡 Intigriti:         \$50 - \$15,000+"
    echo ""

    echo -e "${BLUE}🎯 Platform Specialties:${NC}"
    echo "   🍎 Apple:      iOS/macOS security, zero-click exploits"
    echo "   🔵 Microsoft:  Windows, Azure, Hyper-V vulnerabilities"
    echo "   🔴 Google:     OAuth, same-origin policy, Google services"
    echo "   🔵 HackerOne:  Web apps, business logic, comprehensive"
    echo "   🟠 Bugcrowd:   Crowd validation, all vulnerability types"
    echo "   📱 Samsung:    Mobile devices, Knox security"
    echo "   🟡 Intigriti:  European companies, GDPR compliance"
}

setup_environment() {
    print_header "Setting Up QuantumSentinel Environment"

    # Create results directories
    mkdir -p results/{hackerone,bugcrowd,google_vrp,apple_security,microsoft_msrc,samsung_mobile,intigriti,multi_platform,vendor_programs,crowd_platforms}

    # Make scripts executable
    chmod +x run_multi_platform_bounty.py
    chmod +x run_huntr_bounty.py
    chmod +x platform_quick_commands.sh

    print_success "Environment setup complete!"
    print_info "Results will be saved in ./results/ directory"
}

# =============================================================================
# MAIN COMMAND DISPATCHER
# =============================================================================

case "$1" in
    # HackerOne commands
    "hackerone_web")        hackerone_web "$2" ;;
    "hackerone_mobile")     hackerone_mobile "$2" ;;
    "hackerone_api")        hackerone_api "$2" ;;

    # Bugcrowd commands
    "bugcrowd_comprehensive") bugcrowd_comprehensive "$2" ;;
    "bugcrowd_infrastructure") bugcrowd_infrastructure "$2" ;;

    # Google VRP commands
    "google_web")           google_web "$2" ;;
    "google_android")       google_android "$2" ;;
    "google_api")           google_api "$2" ;;

    # Apple Security commands
    "apple_ios")            apple_ios "$2" ;;
    "apple_macos")          apple_macos "$2" ;;

    # Microsoft MSRC commands
    "microsoft_azure")      microsoft_azure "$2" ;;
    "microsoft_windows")    microsoft_windows "$2" ;;

    # Samsung Mobile commands
    "samsung_device")       samsung_device "$2" ;;

    # Intigriti commands
    "intigriti_gdpr")       intigriti_gdpr "$2" ;;

    # Multi-platform commands
    "test_all_platforms")   test_all_platforms "$2" ;;
    "test_vendor_programs") test_vendor_programs "$2" ;;
    "test_crowd_platforms") test_crowd_platforms "$2" ;;

    # Quick targets
    "target_shopify")       target_shopify ;;
    "target_uber")          target_uber ;;
    "target_google_search") target_google_search ;;
    "target_microsoft_azure") target_microsoft_azure ;;

    # Chaos ProjectDiscovery commands
    "chaos_multi_program")  chaos_multi_program ;;
    "chaos_discover_domains") chaos_discover_domains "$2" ;;

    # HackerOne Mobile Security commands
    "hackerone_mobile_comprehensive") hackerone_mobile_comprehensive ;;

    # Utility commands
    "list_platforms")       list_platforms ;;
    "show_bounty_ranges")   show_bounty_ranges ;;
    "setup_environment")    setup_environment ;;

    # Help
    "help"|"--help"|"-h"|"")
        print_header "QuantumSentinel-Nexus Platform Quick Commands"
        echo "Usage: $0 <command> [target]"
        echo ""
        echo "Quick commands for all major bug bounty platforms:"
        echo ""
        list_platforms
        echo ""
        echo "Utility commands:"
        echo "   • setup_environment          - Setup environment and directories"
        echo "   • list_platforms             - List all supported platforms"
        echo "   • show_bounty_ranges         - Show platform bounty ranges"
        echo "   • chaos_multi_program        - Auto-discover multiple programs via Chaos"
        echo "   • chaos_discover_domains <program> - Discover domains for specific program"
        echo "   • hackerone_mobile_comprehensive - Comprehensive mobile app security scan"
        echo "   • help                       - Show this help message"
        echo ""
        echo "Examples:"
        echo "   $0 hackerone_web https://example.com"
        echo "   $0 google_api https://api.google.com"
        echo "   $0 test_all_platforms https://target.com"
        echo "   $0 target_shopify"
        echo "   $0 chaos_multi_program"
        echo "   $0 chaos_discover_domains shopify"
        echo "   $0 hackerone_mobile_comprehensive"
        ;;

    *)
        print_error "Unknown command: $1"
        echo "Use '$0 help' for available commands"
        exit 1
        ;;
esac