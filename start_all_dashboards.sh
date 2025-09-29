#!/bin/bash

echo "🚀 Starting QuantumSentinel-Nexus Dashboard Services..."
echo "=" * 60

# Kill any existing processes
echo "🔄 Stopping existing services..."
pkill -f "python3.*start-main-dashboard.py" 2>/dev/null
pkill -f "python3.*comprehensive_analysis_server.py" 2>/dev/null
pkill -f "python3.*start-huntr-dashboard.py" 2>/dev/null

sleep 2

# Start services
echo "📊 Starting Main Dashboard (Port 8000)..."
python3 start-main-dashboard.py &

echo "🔬 Starting Comprehensive Analysis Server (Port 8100)..."
python3 comprehensive_analysis_server.py &

echo "🎯 Starting Huntr Dashboard (Port 8009)..."
python3 start-huntr-dashboard.py &

sleep 5

echo ""
echo "✅ Dashboard Services Status:"
echo "=" * 40

# Test each service
if curl -s -o /dev/null -w "" http://127.0.0.1:8000; then
    echo "✅ Main Dashboard: http://127.0.0.1:8000"
else
    echo "❌ Main Dashboard: FAILED"
fi

if curl -s -o /dev/null -w "" http://127.0.0.1:8100; then
    echo "✅ File Analysis: http://127.0.0.1:8100/comprehensive"
else
    echo "❌ File Analysis: FAILED"
fi

if curl -s -o /dev/null -w "" http://127.0.0.1:8009; then
    echo "✅ Huntr Dashboard: http://127.0.0.1:8009/huntr-dashboard"
else
    echo "❌ Huntr Dashboard: FAILED"
fi

echo ""
echo "🎉 All services started! Press Ctrl+C to stop all services."
echo "📱 Open the URLs above in your web browser to access the dashboards."

# Keep script running
trap 'echo ""; echo "🛑 Stopping all services..."; pkill -f "python3.*start-main-dashboard.py"; pkill -f "python3.*comprehensive_analysis_server.py"; pkill -f "python3.*start-huntr-dashboard.py"; echo "✅ Services stopped"; exit 0' INT

while true; do
    sleep 60
done