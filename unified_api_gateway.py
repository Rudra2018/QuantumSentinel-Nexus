#!/usr/bin/env python3
"""
🚀 QuantumSentinel-Nexus: Unified API Gateway
=============================================
Complete API integration for all security modules with workflow orchestration
"""

import json
import os
import time
import base64
import tempfile
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import boto3
from concurrent.futures import ThreadPoolExecutor
import threading
from comprehensive_security_workflow import QuantumSentinelWorkflow

app = Flask(__name__)
CORS(app)

# Global workflow instance
workflow_instance = None
active_analyses = {}
analysis_lock = threading.Lock()

class UnifiedAPIGateway:
    """Unified API Gateway for all security modules"""

    def __init__(self):
        self.aws_session = boto3.Session()
        self.s3_client = self.aws_session.client('s3')
        self.lambda_client = self.aws_session.client('lambda')
        self.executor = ThreadPoolExecutor(max_workers=5)

    def start_analysis(self, file_data: str, filename: str, analysis_config: dict = None) -> dict:
        """Start comprehensive security analysis"""
        analysis_id = f"API-{int(time.time())}"

        # Save uploaded file
        file_content = base64.b64decode(file_data)
        temp_path = os.path.join(tempfile.gettempdir(), f"{analysis_id}_{filename}")

        with open(temp_path, 'wb') as f:
            f.write(file_content)

        # Start analysis in background
        future = self.executor.submit(self._run_analysis, analysis_id, temp_path, analysis_config)

        with analysis_lock:
            active_analyses[analysis_id] = {
                'status': 'RUNNING',
                'start_time': time.time(),
                'filename': filename,
                'future': future,
                'temp_path': temp_path
            }

        return {
            'analysis_id': analysis_id,
            'status': 'STARTED',
            'message': 'Analysis initiated successfully',
            'estimated_time': '5-15 minutes'
        }

    def _run_analysis(self, analysis_id: str, file_path: str, config: dict) -> dict:
        """Run the comprehensive analysis workflow"""
        try:
            workflow = QuantumSentinelWorkflow()
            results = workflow.analyze_file(file_path, config)

            with analysis_lock:
                if analysis_id in active_analyses:
                    active_analyses[analysis_id]['status'] = 'COMPLETED'
                    active_analyses[analysis_id]['results'] = results
                    active_analyses[analysis_id]['end_time'] = time.time()

            # Cleanup temp file
            try:
                os.remove(file_path)
            except:
                pass

            return results

        except Exception as e:
            with analysis_lock:
                if analysis_id in active_analyses:
                    active_analyses[analysis_id]['status'] = 'ERROR'
                    active_analyses[analysis_id]['error'] = str(e)
                    active_analyses[analysis_id]['end_time'] = time.time()

            raise e

    def get_analysis_status(self, analysis_id: str) -> dict:
        """Get analysis status and results"""
        with analysis_lock:
            if analysis_id not in active_analyses:
                return {'error': 'Analysis ID not found'}

            analysis = active_analyses[analysis_id]
            status_info = {
                'analysis_id': analysis_id,
                'status': analysis['status'],
                'filename': analysis['filename'],
                'start_time': analysis['start_time']
            }

            if analysis['status'] == 'COMPLETED':
                status_info['results'] = analysis['results']
                status_info['execution_time'] = analysis['end_time'] - analysis['start_time']
            elif analysis['status'] == 'ERROR':
                status_info['error'] = analysis.get('error', 'Unknown error')
            elif analysis['status'] == 'RUNNING':
                status_info['elapsed_time'] = time.time() - analysis['start_time']

            return status_info

    def list_active_analyses(self) -> dict:
        """List all active analyses"""
        with analysis_lock:
            analyses = []
            for aid, info in active_analyses.items():
                analyses.append({
                    'analysis_id': aid,
                    'status': info['status'],
                    'filename': info['filename'],
                    'start_time': info['start_time'],
                    'elapsed_time': time.time() - info['start_time']
                })

            return {'active_analyses': analyses, 'count': len(analyses)}

# Initialize API Gateway
api_gateway = UnifiedAPIGateway()

@app.route('/')
def dashboard():
    """Serve the unified dashboard"""
    return render_template_string(ENHANCED_DASHBOARD_TEMPLATE)

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Upload file for analysis"""
    try:
        data = request.get_json()

        if 'file_data' not in data or 'filename' not in data:
            return jsonify({'error': 'Missing file_data or filename'}), 400

        result = api_gateway.start_analysis(
            data['file_data'],
            data['filename'],
            data.get('config', {})
        )

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analysis/<analysis_id>', methods=['GET'])
def get_analysis(analysis_id):
    """Get analysis status and results"""
    try:
        result = api_gateway.get_analysis_status(analysis_id)
        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyses', methods=['GET'])
def list_analyses():
    """List all analyses"""
    try:
        result = api_gateway.list_active_analyses()
        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/modules', methods=['GET'])
def get_modules():
    """Get available security modules"""
    global workflow_instance
    if not workflow_instance:
        workflow_instance = QuantumSentinelWorkflow()

    modules = []
    for name, module in workflow_instance.modules.items():
        modules.append({
            'name': name,
            'display_name': module.name,
            'description': module.description,
            'enabled': module.enabled,
            'priority': module.priority,
            'timeout': module.timeout
        })

    return jsonify({'modules': modules})

@app.route('/api/health', methods=['GET'])
def health_check():
    """API health check"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'active_analyses': len(active_analyses),
        'modules_available': 8
    })

# Enhanced Dashboard Template
ENHANCED_DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🚀 QuantumSentinel-Nexus: Live Security Platform</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/feather-icons/dist/feather.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { font-family: 'JetBrains Mono', monospace; scroll-behavior: smooth; }
        body { background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%); min-height: 100vh; overflow-x: hidden; }
        .glass-effect { background: rgba(30, 41, 59, 0.4); backdrop-filter: blur(20px); border: 1px solid rgba(255, 255, 255, 0.1); }
        .upload-zone { border: 2px dashed #22c55e; transition: all 0.3s ease; background: rgba(34, 197, 94, 0.05); }
        .upload-zone:hover, .upload-zone.dragover { border-color: #16a34a; background: rgba(34, 197, 94, 0.1); transform: scale(1.02); }
        .pulse-animation { animation: pulse 2s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.7; } }
    </style>
</head>
<body class="text-gray-100">
    <!-- Header -->
    <div class="bg-gray-900/50 backdrop-blur-sm border-b border-gray-700/50 px-4 sm:px-6 py-4">
        <div class="flex flex-col sm:flex-row items-center justify-between gap-4">
            <div class="flex items-center gap-4">
                <div class="w-12 h-12 bg-gradient-to-r from-blue-500 via-purple-600 to-green-500 rounded-lg flex items-center justify-center">
                    <i data-feather="shield" class="w-7 h-7 text-white"></i>
                </div>
                <div>
                    <h1 class="text-2xl sm:text-3xl font-bold bg-gradient-to-r from-blue-400 via-purple-400 to-green-400 bg-clip-text text-transparent">
                        QuantumSentinel-Nexus
                    </h1>
                    <p class="text-xs sm:text-sm text-gray-400">Live Security Analysis Platform</p>
                </div>
            </div>
            <div class="flex items-center gap-2 sm:gap-4">
                <div class="text-right">
                    <p class="text-sm text-gray-400">Platform Status</p>
                    <p class="text-sm font-medium text-green-400">
                        <span id="status-indicator">🟢 Online</span>
                    </p>
                </div>
                <button onclick="refreshDashboard()" class="px-3 py-2 sm:px-4 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors flex items-center gap-2 text-sm">
                    <i data-feather="refresh-cw" class="w-4 h-4"></i>
                    <span class="hidden sm:inline">Refresh</span>
                </button>
            </div>
        </div>
    </div>

    <!-- Main Dashboard -->
    <div class="p-4 sm:p-6">
        <!-- File Upload Section -->
        <div class="glass-effect rounded-xl p-6 mb-6">
            <h2 class="text-xl font-semibold text-white mb-4 flex items-center gap-2">
                <i data-feather="upload" class="w-5 h-5 text-blue-400"></i>
                Security Analysis Upload
            </h2>

            <div class="upload-zone rounded-lg p-8 text-center mb-4" ondrop="handleDrop(event)" ondragover="handleDragOver(event)" onclick="document.getElementById('fileInput').click()">
                <i data-feather="upload-cloud" class="w-12 h-12 text-green-400 mx-auto mb-4"></i>
                <p class="text-gray-300 mb-2">Drop files here or click to upload</p>
                <p class="text-xs text-gray-400">Supports: APK, IPA, ZIP, JAR, EXE, DLL, SO</p>
                <input type="file" id="fileInput" class="hidden" accept=".apk,.ipa,.zip,.jar,.exe,.dll,.so">
            </div>

            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div class="text-center p-4 bg-blue-600/20 rounded-lg">
                    <div class="text-2xl font-bold text-blue-400" id="total-scans">0</div>
                    <div class="text-xs text-gray-400">Total Scans</div>
                </div>
                <div class="text-center p-4 bg-yellow-600/20 rounded-lg">
                    <div class="text-2xl font-bold text-yellow-400" id="active-scans">0</div>
                    <div class="text-xs text-gray-400">Active Scans</div>
                </div>
                <div class="text-center p-4 bg-green-600/20 rounded-lg">
                    <div class="text-2xl font-bold text-green-400" id="completed-scans">0</div>
                    <div class="text-xs text-gray-400">Completed</div>
                </div>
            </div>
        </div>

        <!-- Security Modules Status -->
        <div class="glass-effect rounded-xl p-6 mb-6">
            <h2 class="text-xl font-semibold text-white mb-4 flex items-center gap-2">
                <i data-feather="cpu" class="w-5 h-5 text-purple-400"></i>
                Security Modules Status
            </h2>
            <div id="modules-grid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <!-- Modules will be loaded here -->
            </div>
        </div>

        <!-- Active Analyses -->
        <div class="glass-effect rounded-xl p-6 mb-6">
            <h2 class="text-xl font-semibold text-white mb-4 flex items-center gap-2">
                <i data-feather="activity" class="w-5 h-5 text-green-400"></i>
                Active Analyses
            </h2>
            <div id="active-analyses-list">
                <p class="text-gray-400 text-center py-8">No active analyses</p>
            </div>
        </div>

        <!-- Recent Results -->
        <div class="glass-effect rounded-xl p-6">
            <h2 class="text-xl font-semibold text-white mb-4 flex items-center gap-2">
                <i data-feather="file-text" class="w-5 h-5 text-yellow-400"></i>
                Recent Analysis Results
            </h2>
            <div id="recent-results">
                <p class="text-gray-400 text-center py-8">No recent results</p>
            </div>
        </div>
    </div>

    <script>
        let analysisPolling = {};

        document.addEventListener('DOMContentLoaded', function() {
            feather.replace();
            loadModules();
            loadActiveAnalyses();
            startStatusPolling();
        });

        function handleDrop(event) {
            event.preventDefault();
            const files = event.dataTransfer.files;
            if (files.length > 0) {
                uploadFile(files[0]);
            }
        }

        function handleDragOver(event) {
            event.preventDefault();
        }

        document.getElementById('fileInput').addEventListener('change', function(event) {
            const file = event.target.files[0];
            if (file) {
                uploadFile(file);
            }
        });

        async function uploadFile(file) {
            const reader = new FileReader();
            reader.onload = async function(event) {
                const base64Data = btoa(event.target.result);

                try {
                    const response = await fetch('/api/upload', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            file_data: base64Data,
                            filename: file.name,
                            config: { priority: 'high' }
                        })
                    });

                    const result = await response.json();
                    if (response.ok) {
                        showNotification('success', `Analysis started: ${result.analysis_id}`);
                        startAnalysisPolling(result.analysis_id);
                        loadActiveAnalyses();
                    } else {
                        showNotification('error', result.error || 'Upload failed');
                    }
                } catch (error) {
                    showNotification('error', 'Network error: ' + error.message);
                }
            };
            reader.readAsBinaryString(file);
        }

        async function loadModules() {
            try {
                const response = await fetch('/api/modules');
                const data = await response.json();

                const grid = document.getElementById('modules-grid');
                grid.innerHTML = data.modules.map(module => `
                    <div class="p-4 bg-gray-800/50 rounded-lg">
                        <div class="flex items-center justify-between mb-2">
                            <h3 class="text-sm font-medium text-white">${module.display_name}</h3>
                            <span class="w-2 h-2 bg-green-400 rounded-full"></span>
                        </div>
                        <p class="text-xs text-gray-400">${module.description}</p>
                        <div class="text-xs text-gray-500 mt-2">Priority: ${module.priority}</div>
                    </div>
                `).join('');

            } catch (error) {
                console.error('Failed to load modules:', error);
            }
        }

        async function loadActiveAnalyses() {
            try {
                const response = await fetch('/api/analyses');
                const data = await response.json();

                const container = document.getElementById('active-analyses-list');
                if (data.active_analyses.length === 0) {
                    container.innerHTML = '<p class="text-gray-400 text-center py-8">No active analyses</p>';
                } else {
                    container.innerHTML = data.active_analyses.map(analysis => `
                        <div class="p-4 bg-gray-800/50 rounded-lg mb-4">
                            <div class="flex items-center justify-between">
                                <div>
                                    <h3 class="text-sm font-medium text-white">${analysis.filename}</h3>
                                    <p class="text-xs text-gray-400">ID: ${analysis.analysis_id}</p>
                                </div>
                                <div class="text-right">
                                    <span class="px-2 py-1 text-xs rounded ${getStatusColor(analysis.status)}">${analysis.status}</span>
                                    <p class="text-xs text-gray-400 mt-1">${Math.floor(analysis.elapsed_time)}s</p>
                                </div>
                            </div>
                        </div>
                    `).join('');
                }

                // Update counters
                document.getElementById('total-scans').textContent = data.count;
                document.getElementById('active-scans').textContent = data.active_analyses.filter(a => a.status === 'RUNNING').length;
                document.getElementById('completed-scans').textContent = data.active_analyses.filter(a => a.status === 'COMPLETED').length;

            } catch (error) {
                console.error('Failed to load analyses:', error);
            }
        }

        function getStatusColor(status) {
            switch(status) {
                case 'RUNNING': return 'bg-yellow-600 text-yellow-100';
                case 'COMPLETED': return 'bg-green-600 text-green-100';
                case 'ERROR': return 'bg-red-600 text-red-100';
                default: return 'bg-gray-600 text-gray-100';
            }
        }

        function startAnalysisPolling(analysisId) {
            if (analysisPolling[analysisId]) return;

            analysisPolling[analysisId] = setInterval(async () => {
                try {
                    const response = await fetch(`/api/analysis/${analysisId}`);
                    const data = await response.json();

                    if (data.status === 'COMPLETED') {
                        clearInterval(analysisPolling[analysisId]);
                        delete analysisPolling[analysisId];
                        showNotification('success', `Analysis completed: ${analysisId}`);
                        loadActiveAnalyses();
                        displayResults(data);
                    } else if (data.status === 'ERROR') {
                        clearInterval(analysisPolling[analysisId]);
                        delete analysisPolling[analysisId];
                        showNotification('error', `Analysis failed: ${data.error}`);
                        loadActiveAnalyses();
                    }
                } catch (error) {
                    console.error('Polling error:', error);
                }
            }, 2000);
        }

        function displayResults(analysisData) {
            const container = document.getElementById('recent-results');
            const resultHtml = `
                <div class="p-4 bg-gray-800/50 rounded-lg mb-4">
                    <div class="flex items-center justify-between mb-4">
                        <h3 class="text-lg font-medium text-white">${analysisData.filename}</h3>
                        <span class="px-3 py-1 text-sm rounded bg-green-600 text-green-100">COMPLETED</span>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                        <div class="text-center">
                            <div class="text-2xl font-bold text-yellow-400">${analysisData.results.analysis_summary.risk_score.toFixed(0)}</div>
                            <div class="text-xs text-gray-400">Risk Score</div>
                        </div>
                        <div class="text-center">
                            <div class="text-2xl font-bold text-red-400">${analysisData.results.analysis_summary.total_findings}</div>
                            <div class="text-xs text-gray-400">Total Findings</div>
                        </div>
                        <div class="text-center">
                            <div class="text-2xl font-bold text-blue-400">${analysisData.results.analysis_summary.modules_executed}</div>
                            <div class="text-xs text-gray-400">Modules Run</div>
                        </div>
                    </div>
                    <button onclick="downloadReport('${analysisData.analysis_id}')" class="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors">
                        Download Full Report
                    </button>
                </div>
            `;
            container.innerHTML = resultHtml + container.innerHTML;
        }

        function downloadReport(analysisId) {
            // Implement report download
            showNotification('info', 'Report download feature coming soon');
        }

        function startStatusPolling() {
            setInterval(() => {
                loadActiveAnalyses();
            }, 5000);
        }

        function refreshDashboard() {
            loadModules();
            loadActiveAnalyses();
            showNotification('info', 'Dashboard refreshed');
        }

        function showNotification(type, message) {
            const notification = document.createElement('div');
            notification.className = `fixed top-4 right-4 px-4 py-2 rounded-lg text-white z-50 ${
                type === 'success' ? 'bg-green-600' :
                type === 'error' ? 'bg-red-600' :
                type === 'info' ? 'bg-blue-600' : 'bg-gray-600'
            }`;
            notification.textContent = message;
            document.body.appendChild(notification);

            setTimeout(() => {
                notification.remove();
            }, 5000);
        }
    </script>
</body>
</html>
'''

if __name__ == '__main__':
    print("🚀 Starting QuantumSentinel-Nexus Unified API Gateway...")
    print("🌐 Dashboard: http://localhost:5000")
    print("📡 API: http://localhost:5000/api")
    app.run(host='0.0.0.0', port=5000, debug=True)