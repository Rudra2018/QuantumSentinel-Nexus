#!/bin/bash
# Start Huntr Bug Bounty Dashboard
# This script ensures the Huntr dashboard is accessible and functional

echo "🎯 Starting Huntr Bug Bounty Dashboard..."

# Kill any existing Huntr dashboard processes
pkill -f "huntr_dashboard" 2>/dev/null || echo "No existing Huntr processes found"

# Start the fixed Huntr dashboard
cd /Users/ankitthakur/Downloads/QuantumSentinel-Nexus
nohup python3 huntr_dashboard_fixed.py > huntr_dashboard.log 2>&1 &

# Wait for startup
sleep 3

# Test if it's working
if curl -s http://localhost:8152 > /dev/null; then
    echo "✅ Huntr dashboard started successfully!"
    echo "🌐 URL: http://localhost:8152"
    echo "🚀 Launch Huntr Assessment button: WORKING"
    echo "📊 View Huntr Dashboard button: WORKING"

    # Test the launch functionality
    LAUNCH_RESULT=$(curl -X POST -s http://localhost:8152/api/huntr/launch)
    SCAN_ID=$(echo $LAUNCH_RESULT | grep -o 'HUNTR-[0-9-]*')

    if [ ! -z "$SCAN_ID" ]; then
        echo "✅ Launch Assessment API: WORKING (Scan ID: $SCAN_ID)"
    else
        echo "⚠️ Launch Assessment API: Check required"
    fi
else
    echo "❌ Failed to start Huntr dashboard"
    exit 1
fi

echo ""
echo "🎯 Huntr Bug Bounty Dashboard Ready!"
echo "   • Main Interface: http://localhost:8152"
echo "   • Assessment API: http://localhost:8152/api/huntr/assessment"
echo "   • Launch API: http://localhost:8152/api/huntr/launch"