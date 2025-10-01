#!/usr/bin/env python3
"""
Chaos Project Discovery Data Loader for QuantumSentinel-Nexus
Processes and loads bug bounty program data from Chaos API
"""

import json
import os
from datetime import datetime
from pathlib import Path
import random

class ChaosDataLoader:
    def __init__(self, data_file="chaos-bugbounty-programs.json"):
        self.data_file = data_file
        self.processed_data = {}
        self.stats = {}

    def load_chaos_data(self):
        """Load and process Chaos Project Discovery bug bounty data"""
        print("🌪️ Loading Chaos Project Discovery bug bounty programs...")

        try:
            with open(self.data_file, 'r') as f:
                chaos_data = json.load(f)

            programs = chaos_data.get('programs', [])
            print(f"📊 Found {len(programs)} bug bounty programs from Chaos")

            # Process programs
            processed_programs = {}

            # Statistics
            bounty_count = 0
            no_bounty_count = 0
            swag_count = 0
            total_domains = 0
            platforms = {}

            for program in programs:
                program_name = program.get('name', '')
                program_url = program.get('url', '')
                has_bounty = program.get('bounty', False)
                has_swag = program.get('swag', False)
                domains = program.get('domains', [])

                # Determine platform from URL
                platform = self.determine_platform(program_url)

                # Generate reward range based on known programs
                reward_range = self.estimate_reward_range(program_name, has_bounty)

                # Count statistics
                if has_bounty:
                    bounty_count += 1
                else:
                    no_bounty_count += 1

                if has_swag:
                    swag_count += 1

                total_domains += len(domains)
                platforms[platform] = platforms.get(platform, 0) + 1

                # Create program entry
                program_id = f"chaos_{program_name.lower().replace(' ', '_').replace('-', '_')}"
                processed_programs[program_id] = {
                    'program_id': program_id,
                    'program_name': program_name,
                    'platform': platform,
                    'program_url': program_url,
                    'has_bounty': has_bounty,
                    'has_swag': has_swag,
                    'reward_range': reward_range,
                    'targets': domains,
                    'target_count': len(domains),
                    'last_updated': datetime.now().isoformat(),
                    'source': 'chaos_project_discovery'
                }

            # Store processed data
            self.processed_data = processed_programs

            # Store statistics
            self.stats = {
                'total_programs': len(programs),
                'bounty_programs': bounty_count,
                'no_bounty_programs': no_bounty_count,
                'swag_programs': swag_count,
                'total_domains': total_domains,
                'avg_domains_per_program': round(total_domains / len(programs), 2) if programs else 0,
                'platforms': platforms,
                'last_updated': datetime.now().isoformat()
            }

            print(f"✅ Processed {len(processed_programs)} programs successfully")
            print(f"💰 Bounty programs: {bounty_count}")
            print(f"🎁 Swag-only programs: {swag_count}")
            print(f"🌐 Total domains: {total_domains}")
            print(f"📈 Platforms found: {len(platforms)}")

            return processed_programs

        except Exception as e:
            print(f"❌ Error loading Chaos data: {e}")
            return {}

    def determine_platform(self, program_url):
        """Determine bug bounty platform from URL"""
        url_lower = program_url.lower()

        if 'hackerone.com' in url_lower:
            return 'HackerOne'
        elif 'bugcrowd.com' in url_lower:
            return 'Bugcrowd'
        elif 'intigriti.com' in url_lower:
            return 'Intigriti'
        elif 'yeswehack.com' in url_lower:
            return 'YesWeHack'
        elif 'hackenproof.com' in url_lower:
            return 'HackenProof'
        elif 'openbugbounty.org' in url_lower:
            return 'Open Bug Bounty'
        elif 'google.com' in url_lower:
            return 'Google VRP'
        elif 'microsoft.com' in url_lower:
            return 'Microsoft MSRC'
        elif 'apple.com' in url_lower:
            return 'Apple Security'
        elif 'facebook.com' in url_lower or 'meta.com' in url_lower:
            return 'Meta Bug Bounty'
        elif 'security' in url_lower or 'responsible' in url_lower:
            return 'Private Program'
        else:
            return 'Other'

    def estimate_reward_range(self, program_name, has_bounty):
        """Estimate reward range based on program name and type"""
        if not has_bounty:
            return "No monetary reward"

        name_lower = program_name.lower()

        # High-value programs (known big tech companies)
        high_value = ['google', 'microsoft', 'apple', 'facebook', 'meta', 'amazon', 'netflix', 'uber', 'tesla', 'shopify', 'paypal', 'coinbase', 'binance', 'github', 'gitlab', 'atlassian', 'salesforce', 'adobe', 'vmware', 'oracle']

        # Medium-value programs
        medium_value = ['slack', 'dropbox', 'spotify', 'twitter', 'linkedin', 'airbnb', 'pinterest', 'snapchat', 'discord', 'reddit', 'yelp', 'mailchimp', 'zendesk', 'okta', 'auth0']

        for company in high_value:
            if company in name_lower:
                return "$10,000 - $100,000+"

        for company in medium_value:
            if company in name_lower:
                return "$1,000 - $25,000"

        # Default ranges based on common patterns
        if any(keyword in name_lower for keyword in ['crypto', 'exchange', 'wallet', 'defi', 'blockchain']):
            return "$5,000 - $50,000"
        elif any(keyword in name_lower for keyword in ['bank', 'financial', 'fintech', 'payment']):
            return "$2,000 - $30,000"
        else:
            return "$100 - $5,000"

    def get_top_programs(self, limit=20, filter_bounty=True):
        """Get top bug bounty programs sorted by domain count"""
        if not self.processed_data:
            self.load_chaos_data()

        programs = list(self.processed_data.values())

        if filter_bounty:
            programs = [p for p in programs if p.get('has_bounty', False)]

        # Sort by target count (descending)
        programs.sort(key=lambda x: x.get('target_count', 0), reverse=True)

        return programs[:limit]

    def get_programs_by_platform(self, platform):
        """Get programs filtered by platform"""
        if not self.processed_data:
            self.load_chaos_data()

        return [p for p in self.processed_data.values() if p.get('platform') == platform]

    def search_programs(self, query):
        """Search programs by name or domain"""
        if not self.processed_data:
            self.load_chaos_data()

        query_lower = query.lower()
        results = []

        for program in self.processed_data.values():
            # Search in program name
            if query_lower in program.get('program_name', '').lower():
                results.append(program)
                continue

            # Search in domains
            for domain in program.get('targets', []):
                if query_lower in domain.lower():
                    results.append(program)
                    break

        return results

    def save_processed_data(self, output_file="chaos_processed_data.json"):
        """Save processed data to file"""
        if not self.processed_data:
            self.load_chaos_data()

        output_data = {
            'metadata': {
                'source': 'Chaos Project Discovery',
                'processed_at': datetime.now().isoformat(),
                'total_programs': len(self.processed_data),
                'stats': self.stats
            },
            'programs': self.processed_data
        }

        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)

        print(f"💾 Processed data saved to {output_file}")
        return output_file

    def generate_dashboard_format(self):
        """Generate data in format expected by bug bounty dashboard"""
        if not self.processed_data:
            self.load_chaos_data()

        dashboard_data = {}

        for program_id, program in self.processed_data.items():
            dashboard_data[program_id] = {
                'program_id': program_id,
                'program_name': program['program_name'],
                'platform': program['platform'],
                'targets': program['targets'],
                'reward_range': program['reward_range'],
                'has_bounty': program['has_bounty'],
                'program_url': program['program_url'],
                'target_count': program['target_count'],
                'last_updated': program['last_updated']
            }

        return dashboard_data

def main():
    """Main function to test the data loader"""
    print("🌪️ Chaos Project Discovery Data Loader")
    print("=" * 50)

    loader = ChaosDataLoader()

    # Load and process data
    programs = loader.load_chaos_data()

    if programs:
        print(f"\n📊 Data Processing Statistics:")
        for key, value in loader.stats.items():
            if key != 'platforms':
                print(f"   {key}: {value}")

        print(f"\n🏆 Top 10 Programs by Domain Count:")
        top_programs = loader.get_top_programs(10)
        for i, program in enumerate(top_programs, 1):
            print(f"   {i}. {program['program_name']} ({program['target_count']} domains) - {program['platform']}")

        print(f"\n🔍 Platform Distribution:")
        for platform, count in sorted(loader.stats['platforms'].items(), key=lambda x: x[1], reverse=True):
            print(f"   {platform}: {count} programs")

        # Save processed data
        loader.save_processed_data()

        print(f"\n✅ Chaos data integration complete!")
    else:
        print("❌ Failed to load Chaos data")

if __name__ == "__main__":
    main()