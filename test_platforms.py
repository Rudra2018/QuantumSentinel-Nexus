#!/usr/bin/env python3
"""
Simple test script for multi-platform bug bounty system
Tests basic functionality without heavy dependencies
"""

import yaml
import json
import os
from pathlib import Path

def load_platform_configs():
    """Load platform configurations from YAML file"""
    try:
        with open('configs/platform_configs.yaml', 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print("❌ Platform configuration file not found!")
        return None

def list_platforms():
    """List all supported platforms"""
    configs = load_platform_configs()
    if not configs:
        return

    print("🎯 Supported Bug Bounty Platforms:")
    print("=" * 50)

    platforms = {
        'hackerone': '🔵 HackerOne',
        'bugcrowd': '🟠 Bugcrowd',
        'intigriti': '🟡 Intigriti',
        'google_vrp': '🔴 Google VRP',
        'apple_security': '🍎 Apple Security',
        'samsung_mobile': '📱 Samsung Mobile',
        'microsoft_msrc': '🔵 Microsoft MSRC'
    }

    for platform_key, platform_name in platforms.items():
        if platform_key in configs:
            config = configs[platform_key]
            platform_info = config.get('platform_info', {})
            bounty_ranges = config.get('bounty_ranges', {})

            print(f"\n{platform_name}")
            print(f"   Type: {platform_info.get('type', 'N/A')}")
            if 'critical' in bounty_ranges:
                print(f"   Critical Bounty: {bounty_ranges['critical']}")
            if 'base_url' in platform_info:
                print(f"   URL: {platform_info['base_url']}")

def show_bounty_summary():
    """Show bounty ranges summary"""
    configs = load_platform_configs()
    if not configs:
        return

    print("\n💰 Bounty Range Summary:")
    print("=" * 50)

    bounty_data = []
    for platform_key, config in configs.items():
        if 'platform_info' in config and 'bounty_ranges' in config:
            platform_name = config['platform_info'].get('name', platform_key)
            critical_range = config['bounty_ranges'].get('critical', 'N/A')
            bounty_data.append((platform_name, critical_range))

    # Sort by potential maximum bounty (rough estimation)
    bounty_data.sort(key=lambda x: extract_max_bounty(x[1]), reverse=True)

    for platform, bounty_range in bounty_data:
        print(f"   {platform}: {bounty_range}")

def extract_max_bounty(bounty_str):
    """Extract maximum bounty value for sorting"""
    if not bounty_str or bounty_str == 'N/A':
        return 0

    # Extract numbers from string like "$5000-$50000+" or "$1000000+"
    import re
    numbers = re.findall(r'\$(\d+)', bounty_str)
    if numbers:
        return max(int(num) for num in numbers)
    return 0

def test_platform_selection(platform_name):
    """Test platform-specific configuration"""
    configs = load_platform_configs()
    if not configs:
        return

    if platform_name not in configs:
        print(f"❌ Platform '{platform_name}' not found!")
        return

    config = configs[platform_name]
    print(f"✅ Testing {config['platform_info']['name']} configuration:")
    print(f"   Platform Type: {config['platform_info']['type']}")
    print(f"   Base URL: {config['platform_info'].get('base_url', 'N/A')}")

    if 'bounty_ranges' in config:
        print("   Bounty Ranges:")
        for severity, range_val in config['bounty_ranges'].items():
            print(f"     {severity.title()}: {range_val}")

    if 'submission_requirements' in config:
        print("   Submission Requirements:")
        for req in config['submission_requirements']:
            print(f"     • {req}")

def main():
    """Main test function"""
    print("🚀 QuantumSentinel-Nexus Multi-Platform Test")
    print("=" * 60)

    # Test configuration loading
    configs = load_platform_configs()
    if configs:
        print("✅ Platform configurations loaded successfully!")
        print(f"   Found {len(configs)} platform configurations")
    else:
        print("❌ Failed to load platform configurations")
        return

    # List all platforms
    list_platforms()

    # Show bounty summary
    show_bounty_summary()

    # Test individual platform
    print("\n🔍 Testing Individual Platform Configuration:")
    print("=" * 50)
    test_platform_selection('hackerone')

    print("\n🎉 Multi-platform system test completed!")
    print("\nNext steps:")
    print("• Use './platform_quick_commands.sh list_platforms' for quick commands")
    print("• Use './platform_quick_commands.sh hackerone_web <target>' to test web apps")
    print("• Use './platform_quick_commands.sh test_all_platforms <target>' for multi-platform testing")

if __name__ == "__main__":
    main()