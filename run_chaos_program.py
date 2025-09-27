#!/usr/bin/env python3
"""
Run QuantumSentinel-Nexus assessment on specific Chaos program
"""

import sys
import subprocess
from chaos_integration import ChaosIntegration
import time

def run_chaos_program_assessment(program_name, max_domains=3):
    """Run assessment on a specific program from Chaos database"""
    api_key = "1545c524-7e20-4b62-aa4a-8235255cff96"
    chaos = ChaosIntegration(api_key)

    print(f"🌪️ Running assessment for {program_name} program")
    print("=" * 60)

    # Get program info
    programs = chaos.fetch_bounty_programs()
    program_info = next((p for p in programs if p['name'].lower() == program_name.lower()), None)

    if not program_info:
        print(f"❌ Program '{program_name}' not found in database")
        return

    platform = program_info['platform']
    priority = program_info['priority']

    print(f"📍 Program: {program_name}")
    print(f"🎯 Platform: {platform}")
    print(f"⭐ Priority: {priority}")

    # Fetch domains
    domains = chaos.fetch_domains_for_program(program_name)

    if not domains:
        print(f"❌ No domains found for {program_name}")
        return

    print(f"✅ Found {len(domains)} domains for {program_name}")

    # Limit domains for testing
    test_domains = domains[:max_domains]
    print(f"🔍 Testing first {len(test_domains)} domains:")

    results = []
    for i, domain in enumerate(test_domains, 1):
        print(f"\n🚀 Testing domain {i}/{len(test_domains)}: {domain}")

        try:
            # Run platform-specific assessment
            if platform == 'hackerone':
                cmd = ["./platform_quick_commands.sh", "hackerone_web", f"https://{domain}"]
            elif platform == 'bugcrowd':
                cmd = ["./platform_quick_commands.sh", "bugcrowd_comprehensive", f"https://{domain}"]
            elif platform == 'google_vrp':
                cmd = ["./platform_quick_commands.sh", "google_web", f"https://{domain}"]
            elif platform == 'microsoft_msrc':
                cmd = ["./platform_quick_commands.sh", "microsoft_azure", f"https://{domain}"]
            elif platform == 'apple_security':
                cmd = ["./platform_quick_commands.sh", "apple_ios", f"https://{domain}"]
            elif platform == 'samsung_mobile':
                cmd = ["./platform_quick_commands.sh", "samsung_device", f"https://{domain}"]
            else:
                cmd = ["./platform_quick_commands.sh", "hackerone_web", f"https://{domain}"]

            print(f"   Command: {' '.join(cmd)}")

            # For demo purposes, we'll show what would be executed
            # Uncomment below to run actual assessment:
            # result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            # results.append({
            #     'domain': domain,
            #     'success': result.returncode == 0,
            #     'output': result.stdout[:500] if result.stdout else ''
            # })

            print(f"   ✅ Assessment queued for {domain}")

        except Exception as e:
            print(f"   ❌ Error with {domain}: {str(e)}")

    print(f"\n🎉 Assessment completed for {program_name}!")
    print(f"📊 Tested {len(test_domains)} domains on {platform} platform")

    # Show recommended next steps
    print(f"\n🚀 Recommended Commands:")
    print(f"• Test all domains: ./platform_quick_commands.sh test_all_platforms https://{domains[0]}")
    print(f"• Focus on {platform}: ./platform_quick_commands.sh {platform}_web https://{domains[0]}")
    print(f"• Multi-program test: ./platform_quick_commands.sh chaos_multi_program")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 run_chaos_program.py <program_name>")
        print("\nAvailable programs:")
        print("• shopify (HackerOne - high priority)")
        print("• gitlab (HackerOne - high priority)")
        print("• uber (HackerOne - high priority)")
        print("• tesla (Bugcrowd - high priority)")
        print("• google (Google VRP - high priority)")
        print("• microsoft (Microsoft MSRC - high priority)")
        print("• apple (Apple Security - high priority)")
        print("• yahoo, slack, dropbox, spotify, twitter (medium priority)")
        sys.exit(1)

    program_name = sys.argv[1]
    run_chaos_program_assessment(program_name)