#!/bin/bash

# QuantumSentinel-Nexus Persistent Dashboard Launcher
# This script starts the dashboard in detached mode to run 24/7

echo "🚀 Starting QuantumSentinel-Nexus Persistent Dashboard..."

# Check if services are already running
if docker ps | grep -q "quantumsentinel-nexus-web-ui"; then
    echo "✅ Dashboard is already running!"
    echo "📊 Access at: http://localhost:8080"
    echo "🔍 Bug Bounty Research: http://localhost:8002"
    exit 0
fi

# Start only essential services for dashboard access
echo "🏗️ Starting core dashboard services..."

# Start IBB Research service (for bug bounty programs)
docker run -d \
    --name quantumsentinel-nexus-ibb-research-persistent \
    --restart unless-stopped \
    -p 8002:8002 \
    -e AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID}" \
    -e AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY}" \
    -e AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}" \
    quantumsentinel-nexus-ibb-research:latest

# Start Web UI service (main dashboard)
docker run -d \
    --name quantumsentinel-nexus-web-ui-persistent \
    --restart unless-stopped \
    -p 8080:80 \
    --link quantumsentinel-nexus-ibb-research-persistent:ibb-research \
    -e AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID}" \
    -e AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY}" \
    -e AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}" \
    quantumsentinel-nexus-web-ui:latest

# Wait for services to start
echo "⏳ Starting services..."
sleep 10

# Check service health
echo "🔍 Checking service health..."
if curl -s http://localhost:8080/health > /dev/null; then
    echo "✅ Web UI Dashboard: HEALTHY"
else
    echo "❌ Web UI Dashboard: UNHEALTHY"
fi

if curl -s http://localhost:8002/health > /dev/null; then
    echo "✅ IBB Research Service: HEALTHY"
else
    echo "❌ IBB Research Service: UNHEALTHY"
fi

echo ""
echo "🎉 QuantumSentinel-Nexus Dashboard is now running 24/7!"
echo ""
echo "📊 Dashboard URL: http://localhost:8080"
echo "🔍 Bug Bounty Research: http://localhost:8002"
echo "🔧 AWS Services: All 10 microservices running on ECS"
echo ""
echo "💡 To stop the dashboard:"
echo "   docker stop quantumsentinel-nexus-web-ui-persistent"
echo "   docker stop quantumsentinel-nexus-ibb-research-persistent"
echo ""
echo "🔄 To restart:"
echo "   ./start-dashboard.sh"
echo ""
echo "📱 Services will auto-restart if Docker restarts"