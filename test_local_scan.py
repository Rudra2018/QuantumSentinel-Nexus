#!/usr/bin/env python3
import subprocess
import sys

def test_local_scan():
    """Test local scanning capabilities"""
    print("🧪 Testing local scan capabilities...")

    # Test platform commands
    try:
        result = subprocess.run(
            ['./platform_quick_commands.sh', 'list_platforms'],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            print("✅ Platform commands working")
            return True
        else:
            print("❌ Platform commands failed")
            return False

    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
        return False

if __name__ == "__main__":
    success = test_local_scan()
    sys.exit(0 if success else 1)
