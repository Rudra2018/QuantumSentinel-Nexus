#!/usr/bin/env python3
"""
🌐 Simple Working Dashboard - Navigation Test
============================================
"""

import boto3
import zipfile
import io

def deploy_simple_working_dashboard():
    """Deploy simple dashboard to test navigation"""
    lambda_client = boto3.client('lambda', region_name='us-east-1')

    simple_dashboard_code = '''
import json
from datetime import datetime

def lambda_handler(event, context):
    """Simple working dashboard"""
    try:
        # Handle CORS preflight requests
        if event.get('httpMethod') == 'OPTIONS':
            return {
                'statusCode': 200,
                'headers': {
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
                    'Access-Control-Max-Age': '86400'
                },
                'body': ''
            }

        # Get the HTTP method and path
        http_method = event.get('httpMethod', 'GET')
        path = event.get('path', '/')

        # Clean up path
        if path.startswith('/prod'):
            path = path[5:]

        if not path:
            path = '/'

        # Serve the dashboard
        if path == '/' or path == '/dashboard':
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'text/html',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': get_simple_dashboard_html()
            }

        # Default response
        else:
            return {
                'statusCode': 404,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({'error': 'Not Found', 'path': path})
            }

    except Exception as e:
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'error': 'Internal server error',
                'message': str(e)
            })
        }

def get_simple_dashboard_html():
    """Generate simple working dashboard HTML"""
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>QuantumSentinel - Working Navigation Test</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 50%, #16213e 100%);
            color: #e0e0e0;
            min-height: 100vh;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            text-align: center;
            box-shadow: 0 4px 8px rgba(0,0,0,0.3);
        }
        .header h1 { color: white; margin-bottom: 10px; font-size: 2.5em; }
        .nav-container {
            background: #1a1a2e;
            padding: 15px 0;
            border-bottom: 2px solid #667eea;
        }
        .nav-buttons {
            display: flex;
            justify-content: center;
            gap: 15px;
            flex-wrap: wrap;
            max-width: 1400px;
            margin: 0 auto;
            padding: 0 20px;
        }
        .nav-btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.3s ease;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }
        .nav-btn:hover {
            background: linear-gradient(135deg, #5a67d8 0%, #6b46c1 100%);
            transform: translateY(-2px);
        }
        .nav-btn.active {
            background: linear-gradient(135deg, #48bb78 0%, #38a169 100%);
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 30px 20px;
        }
        .section {
            display: none;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            border-radius: 12px;
            padding: 30px;
            margin: 20px 0;
            border: 1px solid #2d3748;
        }
        .section.active {
            display: block;
        }
        .section h2 {
            color: #64ffda;
            margin-bottom: 20px;
            font-size: 1.8em;
            text-align: center;
        }
        .test-info {
            background: rgba(0,255,0,0.1);
            border: 1px solid #48bb78;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }
        .test-info h3 {
            color: #48bb78;
            margin-bottom: 10px;
        }
        .logs {
            background: #0a0a0a;
            color: #00ff00;
            padding: 20px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            max-height: 300px;
            overflow-y: auto;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 QuantumSentinel - Navigation Test</h1>
        <p>Testing Navigation Button Functionality</p>
    </div>

    <div class="nav-container">
        <div class="nav-buttons">
            <button class="nav-btn active" onclick="showSection('dashboard')">🏠 Dashboard</button>
            <button class="nav-btn" onclick="showSection('url-scan')">🔍 URL Scanner</button>
            <button class="nav-btn" onclick="showSection('upload')">📁 File Upload</button>
            <button class="nav-btn" onclick="showSection('bounty')">🏆 Bug Bounty</button>
            <button class="nav-btn" onclick="showSection('scans')">🔍 Security Scans</button>
            <button class="nav-btn" onclick="showSection('ml')">🧠 ML Intelligence</button>
            <button class="nav-btn" onclick="showSection('research')">🔬 IBB Research</button>
            <button class="nav-btn" onclick="showSection('fuzzing')">⚡ Fuzzing</button>
            <button class="nav-btn" onclick="showSection('reports')">📊 Reports</button>
            <button class="nav-btn" onclick="showSection('monitoring')">📈 Monitoring</button>
            <button class="nav-btn" onclick="showSection('settings')">⚙️ Settings</button>
        </div>
    </div>

    <div class="container">
        <!-- Dashboard Section -->
        <div id="dashboard-section" class="section active">
            <h2>🏠 Dashboard - Working!</h2>
            <div class="test-info">
                <h3>✅ Navigation Test Status</h3>
                <p>Dashboard section is displaying correctly. Navigation buttons should work now.</p>
                <p>Click any button above to test navigation functionality.</p>
            </div>
            <div class="logs" id="activity-logs">
                <div>🔐 QuantumSentinel Navigation Test - System Ready</div>
                <div>✅ Dashboard section loaded successfully</div>
                <div>🔧 Click any navigation button to test functionality</div>
            </div>
        </div>

        <!-- URL Scanner Section -->
        <div id="url-scan-section" class="section">
            <h2>🔍 URL Scanner - Working!</h2>
            <div class="test-info">
                <h3>✅ URL Scanner Section</h3>
                <p>URL Scanner navigation is working correctly!</p>
                <p>This section will contain the enhanced POC scanning functionality.</p>
            </div>
        </div>

        <!-- File Upload Section -->
        <div id="upload-section" class="section">
            <h2>📁 File Upload - Working!</h2>
            <div class="test-info">
                <h3>✅ File Upload Section</h3>
                <p>File Upload navigation is working correctly!</p>
                <p>This section will contain file analysis functionality.</p>
            </div>
        </div>

        <!-- Bug Bounty Section -->
        <div id="bounty-section" class="section">
            <h2>🏆 Bug Bounty - Working!</h2>
            <div class="test-info">
                <h3>✅ Bug Bounty Section</h3>
                <p>Bug Bounty navigation is working correctly!</p>
                <p>This section will contain Huntr.com integration and research tools.</p>
            </div>
        </div>

        <!-- Security Scans Section -->
        <div id="scans-section" class="section">
            <h2>🔍 Security Scans - Working!</h2>
            <div class="test-info">
                <h3>✅ Security Scans Section</h3>
                <p>Security Scans navigation is working correctly!</p>
                <p>This section will contain multi-engine security testing.</p>
            </div>
        </div>

        <!-- ML Intelligence Section -->
        <div id="ml-section" class="section">
            <h2>🧠 ML Intelligence - Working!</h2>
            <div class="test-info">
                <h3>✅ ML Intelligence Section</h3>
                <p>ML Intelligence navigation is working correctly!</p>
                <p>This section will contain AI-powered security analysis.</p>
            </div>
        </div>

        <!-- IBB Research Section -->
        <div id="research-section" class="section">
            <h2>🔬 IBB Research - Working!</h2>
            <div class="test-info">
                <h3>✅ IBB Research Section</h3>
                <p>IBB Research navigation is working correctly!</p>
                <p>This section will contain intelligent bug bounty research.</p>
            </div>
        </div>

        <!-- Fuzzing Section -->
        <div id="fuzzing-section" class="section">
            <h2>⚡ Fuzzing - Working!</h2>
            <div class="test-info">
                <h3>✅ Fuzzing Section</h3>
                <p>Fuzzing navigation is working correctly!</p>
                <p>This section will contain advanced fuzzing capabilities.</p>
            </div>
        </div>

        <!-- Reports Section -->
        <div id="reports-section" class="section">
            <h2>📊 Reports - Working!</h2>
            <div class="test-info">
                <h3>✅ Reports Section</h3>
                <p>Reports navigation is working correctly!</p>
                <p>This section will contain comprehensive security reports.</p>
            </div>
        </div>

        <!-- Monitoring Section -->
        <div id="monitoring-section" class="section">
            <h2>📈 Monitoring - Working!</h2>
            <div class="test-info">
                <h3>✅ Monitoring Section</h3>
                <p>Monitoring navigation is working correctly!</p>
                <p>This section will contain real-time security monitoring.</p>
            </div>
        </div>

        <!-- Settings Section -->
        <div id="settings-section" class="section">
            <h2>⚙️ Settings - Working!</h2>
            <div class="test-info">
                <h3>✅ Settings Section</h3>
                <p>Settings navigation is working correctly!</p>
                <p>This section will contain platform configuration options.</p>
            </div>
        </div>
    </div>

    <script>
        function showSection(sectionName) {
            console.log('showSection called with:', sectionName);

            // Remove active class from all nav buttons
            document.querySelectorAll('.nav-btn').forEach(btn => {
                btn.classList.remove('active');
            });

            // Add active class to clicked button
            event.target.classList.add('active');

            // Hide all sections
            document.querySelectorAll('.section').forEach(section => {
                section.classList.remove('active');
            });

            // Show selected section
            const targetSection = document.getElementById(sectionName + '-section');
            if (targetSection) {
                targetSection.classList.add('active');
                addLog(`✅ Navigated to ${sectionName} section successfully`);
            } else {
                addLog(`❌ Section ${sectionName} not found`);
            }
        }

        function addLog(message) {
            const logsPanel = document.getElementById('activity-logs');
            if (logsPanel) {
                const timestamp = new Date().toLocaleTimeString();
                const logEntry = document.createElement('div');
                logEntry.textContent = `[${timestamp}] ${message}`;
                logsPanel.appendChild(logEntry);
                logsPanel.scrollTop = logsPanel.scrollHeight;
            }
        }

        // Test navigation on page load
        document.addEventListener('DOMContentLoaded', function() {
            addLog('🚀 Navigation system initialized');
            addLog('🔧 All buttons should be clickable');
            addLog('📋 Test each button to verify functionality');
        });
    </script>
</body>
</html>"""
'''

    # Create ZIP file for Lambda deployment
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr('lambda_function.py', simple_dashboard_code)

    zip_buffer.seek(0)

    try:
        # Force update the Lambda function
        response = lambda_client.update_function_code(
            FunctionName='quantumsentinel-unified-dashboard',
            ZipFile=zip_buffer.read()
        )
        print("✅ Simple working dashboard deployed successfully!")
        print(f"   Function ARN: {response['FunctionArn']}")
        print(f"   Code Size: {response['CodeSize']} bytes")
        print(f"   Last Modified: {response['LastModified']}")

    except Exception as e:
        print(f"❌ Deployment failed: {str(e)}")
        return

    print("\n🌐 Simple Working Dashboard Features:")
    print("   ✅ Basic navigation system")
    print("   ✅ Each button shows different section")
    print("   ✅ Real-time activity logging")
    print("   ✅ Visual feedback on navigation")
    print("\n🚀 Access working dashboard:")
    print("   URL: https://ex57j8i2bi.execute-api.us-east-1.amazonaws.com/prod")
    print("   All 11 navigation buttons should work now!")

if __name__ == "__main__":
    deploy_simple_working_dashboard()