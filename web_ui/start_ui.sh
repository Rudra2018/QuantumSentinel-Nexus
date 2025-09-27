#!/bin/bash

# QuantumSentinel-Nexus Web UI Startup Script

echo "🚀 QuantumSentinel-Nexus Web UI"
echo "================================"

# Check if we're in the right directory
if [ ! -f "index.html" ]; then
    echo "❌ Error: index.html not found. Please run this script from the web_ui directory."
    exit 1
fi

# Check Python installation
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is required but not installed."
    exit 1
fi

# Install required Python packages
echo "📦 Installing Python dependencies..."
pip3 install flask flask-cors requests > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo "✅ Dependencies installed successfully"
else
    echo "⚠️  Warning: Failed to install some dependencies. The UI may not work properly."
fi

# Check if port 8080 is available
if lsof -Pi :8080 -sTCP:LISTEN -t >/dev/null ; then
    echo "⚠️  Warning: Port 8080 is already in use. The server may fail to start."
fi

echo ""
echo "🌟 Starting QuantumSentinel-Nexus Web UI..."
echo "📍 URL: http://localhost:8080"
echo "🛑 Press Ctrl+C to stop"
echo ""

# Start the Flask server
python3 server.py