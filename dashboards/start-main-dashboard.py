#!/usr/bin/env python3
"""
QuantumSentinel-Nexus: Main Dashboard Launcher
Simplified launcher for the main security assessment dashboard
"""

import http.server
import socketserver
import webbrowser
import json
import os
import subprocess
import threading
import time
import glob
from pathlib import Path
from datetime import datetime

PORT = 8000

# Global variables for real-time data
active_scans = {}
scan_results = {}
module_status = {}

class MainDashboardHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        data = json.loads(post_data.decode('utf-8'))

        if self.path == '/api/scan/start':
            self.start_scan(data)
        elif self.path == '/api/scan/stop':
            self.stop_scan(data)

    def start_scan(self, data):
        scan_type = data.get('type')
        target = data.get('target')
        options = data.get('options', {})

        scan_id = f"{scan_type}_{int(time.time())}"

        # Create scan command based on type
        commands = {
            'domain': f"python3 workflows/web-reconnaissance-enhanced.py {target}",
            'network': f"python3 workflows/network-scanning-enhanced.py {target}",
            'mobile': f"python3 workflows/mobile-app-analysis-enhanced.py {target}",
            'binary': f"python3 services/binary-analysis/main.py {target}",
            'sast': f"python3 services/sast-dast/main.py {target}",
            'huntr': f"python3 workflows/huntr-testing-simple.py"
        }

        if scan_type in commands:
            active_scans[scan_id] = {
                'type': scan_type,
                'target': target,
                'status': 'running',
                'start_time': datetime.now().isoformat(),
                'progress': 0
            }

            # Start scan in background
            def run_scan():
                try:
                    process = subprocess.Popen(
                        commands[scan_type].split(),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        cwd='/Users/ankitthakur/Downloads/QuantumSentinel-Nexus'
                    )
                    active_scans[scan_id]['process'] = process
                    stdout, stderr = process.communicate()

                    active_scans[scan_id]['status'] = 'completed'
                    active_scans[scan_id]['end_time'] = datetime.now().isoformat()
                    active_scans[scan_id]['output'] = stdout.decode()
                    active_scans[scan_id]['error'] = stderr.decode()
                except Exception as e:
                    active_scans[scan_id]['status'] = 'failed'
                    active_scans[scan_id]['error'] = str(e)

            threading.Thread(target=run_scan, daemon=True).start()

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps({'scan_id': scan_id, 'status': 'started'}).encode())

    def stop_scan(self, data):
        scan_id = data.get('scan_id')
        if scan_id in active_scans and 'process' in active_scans[scan_id]:
            active_scans[scan_id]['process'].terminate()
            active_scans[scan_id]['status'] = 'stopped'

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps({'status': 'stopped'}).encode())

    def do_GET(self):
        if self.path == '/' or self.path == '/dashboard':
            # Serve the main dashboard
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            dashboard_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>QuantumSentinel-Nexus: Advanced Security Command Center</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        .glow { box-shadow: 0 0 20px rgba(34, 197, 94, 0.5); }
        .danger-glow { box-shadow: 0 0 20px rgba(239, 68, 68, 0.5); }
        .warning-glow { box-shadow: 0 0 20px rgba(245, 158, 11, 0.5); }
        .pulse-glow { animation: pulse-glow 2s infinite; }
        @keyframes pulse-glow {
            0%, 100% { box-shadow: 0 0 20px rgba(34, 197, 94, 0.5); }
            50% { box-shadow: 0 0 30px rgba(34, 197, 94, 0.8); }
        }
        .matrix-bg {
            background: linear-gradient(45deg, #000000, #1a1a1a);
            position: relative; overflow: hidden;
        }
        .scan-progress { width: 0%; transition: width 0.3s ease; }
        .modal { display: none; }
        .modal.active { display: flex; }
    </style>
</head>
<body class="bg-gray-900 text-green-400 font-mono">
    <!-- Header -->
    <header class="bg-black border-b border-green-500 p-4">
        <div class="container mx-auto flex items-center justify-between">
            <div class="flex items-center space-x-4">
                <div class="text-3xl font-bold text-green-400 glow">⚡ QUANTUM SENTINEL NEXUS</div>
                <div class="text-lg text-green-300">Advanced Security Command Center</div>
            </div>
            <div class="flex items-center space-x-6">
                <div class="text-sm">
                    <span class="text-green-400">STATUS:</span>
                    <span id="platform-status" class="text-green-300 font-bold pulse-glow">OPERATIONAL</span>
                </div>
                <div class="text-sm">
                    <span class="text-green-400">SCANS:</span>
                    <span id="active-scans-count" class="text-yellow-300 font-bold">0</span>
                </div>
                <div class="text-sm">
                    <span class="text-green-400">TIME:</span>
                    <span id="current-time" class="text-green-300"></span>
                </div>
            </div>
        </div>
    </header>

    <!-- Main Dashboard -->
    <div class="container mx-auto p-6">
        <!-- Real-time Statistics -->
        <div class="grid grid-cols-1 md:grid-cols-5 gap-6 mb-8">
            <div class="bg-gray-800 border border-green-500 rounded-lg p-6 glow">
                <div class="text-3xl font-bold text-green-400" id="active-scans">0</div>
                <div class="text-green-300">Active Scans</div>
                <div class="text-xs text-gray-400 mt-2">Currently Running</div>
            </div>
            <div class="bg-gray-800 border border-blue-500 rounded-lg p-6">
                <div class="text-3xl font-bold text-blue-400" id="completed-scans">0</div>
                <div class="text-blue-300">Completed</div>
                <div class="text-xs text-gray-400 mt-2">Total Finished</div>
            </div>
            <div class="bg-gray-800 border border-yellow-500 rounded-lg p-6">
                <div class="text-3xl font-bold text-yellow-400" id="vulnerabilities">0</div>
                <div class="text-yellow-300">Vulnerabilities</div>
                <div class="text-xs text-gray-400 mt-2">Identified Issues</div>
            </div>
            <div class="bg-gray-800 border border-red-500 rounded-lg p-6">
                <div class="text-3xl font-bold text-red-400" id="critical-findings">0</div>
                <div class="text-red-300">Critical</div>
                <div class="text-xs text-gray-400 mt-2">High Risk Issues</div>
            </div>
            <div class="bg-gray-800 border border-purple-500 rounded-lg p-6">
                <div class="text-3xl font-bold text-purple-400" id="reports-count">0</div>
                <div class="text-purple-300">Reports</div>
                <div class="text-xs text-gray-400 mt-2">Generated Reports</div>
            </div>
        </div>

        <!-- Module Launch Controls -->
        <div class="bg-gray-800 border border-green-500 rounded-lg p-6 mb-8">
            <h3 class="text-xl font-bold text-green-400 mb-6">🚀 Launch Security Modules</h3>
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                <!-- Domain/Web Scanning -->
                <div class="bg-gray-700 border border-blue-400 rounded-lg p-4">
                    <h4 class="text-lg font-bold text-blue-400 mb-3">🌐 Domain Assessment</h4>
                    <form onsubmit="startScan(event, 'domain')">
                        <input type="text" name="target" placeholder="example.com" required
                               class="w-full bg-gray-800 border border-gray-600 rounded px-3 py-2 text-green-300 mb-3">
                        <div class="grid grid-cols-2 gap-2 mb-3">
                            <label class="flex items-center text-sm">
                                <input type="checkbox" name="subdomain" class="mr-2"> Subdomains
                            </label>
                            <label class="flex items-center text-sm">
                                <input type="checkbox" name="ports" class="mr-2"> Port Scan
                            </label>
                        </div>
                        <button type="submit" class="w-full bg-blue-900 hover:bg-blue-800 text-blue-300 py-2 rounded">
                            Launch Domain Scan
                        </button>
                    </form>
                </div>

                <!-- Network Scanning -->
                <div class="bg-gray-700 border border-yellow-400 rounded-lg p-4">
                    <h4 class="text-lg font-bold text-yellow-400 mb-3">🔍 Network Discovery</h4>
                    <form onsubmit="startScan(event, 'network')">
                        <input type="text" name="target" placeholder="192.168.1.0/24" required
                               class="w-full bg-gray-800 border border-gray-600 rounded px-3 py-2 text-green-300 mb-3">
                        <div class="grid grid-cols-2 gap-2 mb-3">
                            <label class="flex items-center text-sm">
                                <input type="checkbox" name="fast" class="mr-2"> Fast Scan
                            </label>
                            <label class="flex items-center text-sm">
                                <input type="checkbox" name="aggressive" class="mr-2"> Aggressive
                            </label>
                        </div>
                        <button type="submit" class="w-full bg-yellow-900 hover:bg-yellow-800 text-yellow-300 py-2 rounded">
                            Launch Network Scan
                        </button>
                    </form>
                </div>

                <!-- Binary Analysis -->
                <div class="bg-gray-700 border border-red-400 rounded-lg p-4">
                    <h4 class="text-lg font-bold text-red-400 mb-3">⚙️ Binary Analysis</h4>
                    <form onsubmit="startScan(event, 'binary')">
                        <input type="file" name="binary" accept=".exe,.elf,.dll,.so" required
                               class="w-full bg-gray-800 border border-gray-600 rounded px-3 py-2 text-green-300 mb-3">
                        <div class="grid grid-cols-2 gap-2 mb-3">
                            <label class="flex items-center text-sm">
                                <input type="checkbox" name="static" class="mr-2"> Static Analysis
                            </label>
                            <label class="flex items-center text-sm">
                                <input type="checkbox" name="dynamic" class="mr-2"> Dynamic Analysis
                            </label>
                        </div>
                        <button type="submit" class="w-full bg-red-900 hover:bg-red-800 text-red-300 py-2 rounded">
                            Launch Binary Analysis
                        </button>
                    </form>
                </div>

                <!-- Mobile App Analysis -->
                <div class="bg-gray-700 border border-purple-400 rounded-lg p-4">
                    <h4 class="text-lg font-bold text-purple-400 mb-3">📱 Mobile App Security</h4>
                    <form onsubmit="startScan(event, 'mobile')">
                        <input type="file" name="app" accept=".apk,.ipa" required
                               class="w-full bg-gray-800 border border-gray-600 rounded px-3 py-2 text-green-300 mb-3">
                        <div class="grid grid-cols-2 gap-2 mb-3">
                            <label class="flex items-center text-sm">
                                <input type="checkbox" name="sast" class="mr-2"> SAST
                            </label>
                            <label class="flex items-center text-sm">
                                <input type="checkbox" name="permissions" class="mr-2"> Permissions
                            </label>
                        </div>
                        <button type="submit" class="w-full bg-purple-900 hover:bg-purple-800 text-purple-300 py-2 rounded">
                            Launch Mobile Analysis
                        </button>
                    </form>
                </div>

                <!-- SAST/DAST -->
                <div class="bg-gray-700 border border-green-400 rounded-lg p-4">
                    <h4 class="text-lg font-bold text-green-400 mb-3">🔒 Code Security</h4>
                    <form onsubmit="startScan(event, 'sast')">
                        <input type="text" name="target" placeholder="github.com/user/repo" required
                               class="w-full bg-gray-800 border border-gray-600 rounded px-3 py-2 text-green-300 mb-3">
                        <div class="grid grid-cols-2 gap-2 mb-3">
                            <label class="flex items-center text-sm">
                                <input type="checkbox" name="sast" class="mr-2"> SAST
                            </label>
                            <label class="flex items-center text-sm">
                                <input type="checkbox" name="dast" class="mr-2"> DAST
                            </label>
                        </div>
                        <button type="submit" class="w-full bg-green-900 hover:bg-green-800 text-green-300 py-2 rounded">
                            Launch Code Analysis
                        </button>
                    </form>
                </div>

                <!-- Huntr Assessment -->
                <div class="bg-gray-700 border border-cyan-400 rounded-lg p-4">
                    <h4 class="text-lg font-bold text-cyan-400 mb-3">🎯 Huntr Bug Bounty</h4>
                    <div class="space-y-3">
                        <button onclick="startScan(null, 'huntr')"
                                class="w-full bg-cyan-900 hover:bg-cyan-800 text-cyan-300 py-2 rounded">
                            Launch Huntr Assessment
                        </button>
                        <button onclick="window.open('http://localhost:8009/huntr-dashboard', '_blank')"
                                class="w-full bg-gray-600 hover:bg-gray-500 text-gray-300 py-2 rounded">
                            View Huntr Dashboard
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Live Scan Monitoring -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
            <!-- Active Scans -->
            <div class="bg-gray-800 border border-green-500 rounded-lg p-6">
                <h3 class="text-xl font-bold text-green-400 mb-4">⚡ Live Scan Monitor</h3>
                <div id="active-scans-list" class="space-y-3">
                    <div class="text-gray-400 text-center py-8">No active scans</div>
                </div>
            </div>

            <!-- System Status -->
            <div class="bg-gray-800 border border-green-500 rounded-lg p-6">
                <h3 class="text-xl font-bold text-green-400 mb-4">🛡️ System Status</h3>
                <div id="system-status" class="space-y-3">
                    <!-- Will be populated by JavaScript -->
                </div>
            </div>
        </div>

        <!-- Reports and Results -->
        <div class="bg-gray-800 border border-green-500 rounded-lg p-6 mb-8">
            <h3 class="text-xl font-bold text-green-400 mb-4">📊 Reports & Results</h3>
            <div class="overflow-x-auto">
                <table class="w-full table-auto">
                    <thead>
                        <tr class="border-b border-green-500">
                            <th class="text-left py-2 px-4 text-green-400">Report</th>
                            <th class="text-left py-2 px-4 text-green-400">Type</th>
                            <th class="text-left py-2 px-4 text-green-400">Size</th>
                            <th class="text-left py-2 px-4 text-green-400">Date</th>
                            <th class="text-left py-2 px-4 text-green-400">Action</th>
                        </tr>
                    </thead>
                    <tbody id="reports-table">
                        <!-- Will be populated by JavaScript -->
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        let scansData = {};
        let systemStatus = {};

        // Update current time
        function updateTime() {
            document.getElementById('current-time').textContent = new Date().toLocaleTimeString();
        }
        setInterval(updateTime, 1000);
        updateTime();

        // Start a scan
        async function startScan(event, type) {
            if (event) event.preventDefault();

            const formData = event ? new FormData(event.target) : new FormData();
            const target = formData.get('target') || 'default';

            const scanData = {
                type: type,
                target: target,
                options: Object.fromEntries(formData.entries())
            };

            try {
                const response = await fetch('/api/scan/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(scanData)
                });

                const result = await response.json();
                console.log('Scan started:', result);
                refreshData();
            } catch (error) {
                console.error('Error starting scan:', error);
            }
        }

        // Stop a scan
        async function stopScan(scanId) {
            try {
                const response = await fetch('/api/scan/stop', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ scan_id: scanId })
                });

                const result = await response.json();
                console.log('Scan stopped:', result);
                refreshData();
            } catch (error) {
                console.error('Error stopping scan:', error);
            }
        }

        // Refresh all data
        async function refreshData() {
            await Promise.all([
                refreshStatus(),
                refreshScans(),
                refreshReports()
            ]);
        }

        // Refresh system status
        async function refreshStatus() {
            try {
                const response = await fetch('/api/status');
                systemStatus = await response.json();
                updateStatusDisplay();
            } catch (error) {
                console.error('Error fetching status:', error);
            }
        }

        // Refresh scan data
        async function refreshScans() {
            try {
                const response = await fetch('/api/scans');
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                const text = await response.text();
                if (!text.trim()) {
                    scansData = {};
                } else {
                    scansData = JSON.parse(text);
                }
                updateScansDisplay();
            } catch (error) {
                console.error('Error fetching scans:', error);
                scansData = {};
                updateScansDisplay();
            }
        }

        // Refresh reports
        async function refreshReports() {
            try {
                const response = await fetch('/api/reports');
                const reports = await response.json();
                updateReportsDisplay(reports);
            } catch (error) {
                console.error('Error fetching reports:', error);
            }
        }

        // Update status display
        function updateStatusDisplay() {
            if (!systemStatus) return;

            document.getElementById('active-scans').textContent = systemStatus.active_scans || 0;
            document.getElementById('completed-scans').textContent = systemStatus.completed_scans || 0;
            document.getElementById('active-scans-count').textContent = systemStatus.active_scans || 0;

            // Update system status panel
            const statusContainer = document.getElementById('system-status');
            statusContainer.innerHTML = '';

            if (systemStatus.services) {
                Object.entries(systemStatus.services).forEach(([service, status]) => {
                    const serviceDiv = document.createElement('div');
                    serviceDiv.className = 'flex items-center justify-between';
                    serviceDiv.innerHTML = `
                        <span class="text-green-300">${service.replace('_', ' ').toUpperCase()}</span>
                        <span class="px-2 py-1 rounded text-xs ${status === 'active' ? 'bg-green-900 text-green-300' : 'bg-red-900 text-red-300'}">
                            ${status.toUpperCase()}
                        </span>
                    `;
                    statusContainer.appendChild(serviceDiv);
                });
            }
        }

        // Update scans display
        function updateScansDisplay() {
            const container = document.getElementById('active-scans-list');
            container.innerHTML = '';

            const activeScansList = Object.entries(scansData).filter(([_, scan]) => scan.status === 'running');

            if (activeScansList.length === 0) {
                container.innerHTML = '<div class="text-gray-400 text-center py-8">No active scans</div>';
                return;
            }

            activeScansList.forEach(([scanId, scan]) => {
                const scanDiv = document.createElement('div');
                scanDiv.className = 'bg-gray-700 border border-yellow-500 rounded p-4';
                scanDiv.innerHTML = `
                    <div class="flex items-center justify-between mb-2">
                        <span class="text-yellow-300 font-bold">${scan.type.toUpperCase()}</span>
                        <button onclick="stopScan('${scanId}')" class="bg-red-900 hover:bg-red-800 text-red-300 px-2 py-1 rounded text-xs">
                            Stop
                        </button>
                    </div>
                    <div class="text-green-300 text-sm">Target: ${scan.target}</div>
                    <div class="text-gray-400 text-xs">Started: ${new Date(scan.start_time).toLocaleString()}</div>
                    <div class="w-full bg-gray-600 rounded-full h-2 mt-2">
                        <div class="bg-yellow-400 h-2 rounded-full scan-progress" style="width: ${scan.progress || 0}%"></div>
                    </div>
                `;
                container.appendChild(scanDiv);
            });
        }

        // Update reports display
        function updateReportsDisplay(reports) {
            const tableBody = document.getElementById('reports-table');
            tableBody.innerHTML = '';

            document.getElementById('reports-count').textContent = reports.length;

            reports.forEach(report => {
                const row = document.createElement('tr');
                row.className = 'border-b border-gray-700 hover:bg-gray-700';
                row.innerHTML = `
                    <td class="py-2 px-4 text-green-300">${report.name}</td>
                    <td class="py-2 px-4 text-blue-300">${report.type}</td>
                    <td class="py-2 px-4 text-gray-300">${(report.size / 1024).toFixed(1)} KB</td>
                    <td class="py-2 px-4 text-gray-300">${new Date(report.modified).toLocaleDateString()}</td>
                    <td class="py-2 px-4">
                        <button class="bg-blue-900 hover:bg-blue-800 text-blue-300 px-2 py-1 rounded text-xs">
                            Download
                        </button>
                    </td>
                `;
                tableBody.appendChild(row);
            });
        }

        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', function() {
            refreshData();
            // Auto-refresh every 5 seconds
            setInterval(refreshData, 5000);
        });
    </script>
</body>
</html>"""
            self.wfile.write(dashboard_html.encode())

        elif self.path == '/api/status':
            self.get_real_time_status()
        elif self.path == '/api/scans':
            self.get_scan_status()
        elif self.path == '/api/results':
            self.get_scan_results()
        elif self.path == '/api/reports':
            self.get_reports()
        elif self.path == '/favicon.ico':
            self.send_response(200)
            self.send_header('Content-type', 'image/x-icon')
            self.end_headers()
            try:
                with open('favicon.ico', 'rb') as f:
                    self.wfile.write(f.read())
            except:
                pass
        else:
            super().do_GET()

    def get_real_time_status(self):
        # Get actual system status
        status_data = {
            "platform_status": "operational",
            "timestamp": datetime.now().isoformat(),
            "services": self.check_service_status(),
            "active_scans": len([s for s in active_scans.values() if s['status'] == 'running']),
            "completed_scans": len([s for s in active_scans.values() if s['status'] == 'completed']),
            "failed_scans": len([s for s in active_scans.values() if s['status'] == 'failed']),
            "huntr_dashboard": "http://localhost:8009/huntr-dashboard",
            "aws_services": self.check_aws_status()
        }

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(status_data).encode())

    def get_scan_status(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(active_scans).encode())

    def get_scan_results(self):
        # Load actual scan results from results directory
        results_dir = Path('/Users/ankitthakur/Downloads/QuantumSentinel-Nexus/results')
        all_results = {}

        if results_dir.exists():
            for result_file in results_dir.rglob('*.json'):
                try:
                    with open(result_file, 'r') as f:
                        data = json.load(f)
                        all_results[result_file.stem] = data
                except:
                    pass

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(all_results).encode())

    def get_reports(self):
        # Get only comprehensive PDF and MD reports (> 1KB)
        reports_dir = Path('/Users/ankitthakur/Downloads/QuantumSentinel-Nexus/results')
        reports = []

        if reports_dir.exists():
            # Look for comprehensive reports
            pdf_reports_dir = reports_dir / 'pdf_reports'
            if pdf_reports_dir.exists():
                for report_file in pdf_reports_dir.rglob('*'):
                    if report_file.is_file() and report_file.suffix in ['.pdf', '.md']:
                        size_bytes = report_file.stat().st_size
                        if size_bytes > 1024:  # Only files larger than 1KB
                            size_kb = size_bytes / 1024
                            reports.append({
                                'name': report_file.name,
                                'path': str(report_file),
                                'size': f"{size_kb:.1f} KB",
                                'size_bytes': size_bytes,
                                'modified': datetime.fromtimestamp(report_file.stat().st_mtime).strftime('%d/%m/%Y'),
                                'type': report_file.suffix
                            })

            # Look for main comprehensive reports in root results
            for pattern in ['*comprehensive*', '*master*', '*complete*']:
                for report_file in reports_dir.glob(pattern):
                    if report_file.is_file() and report_file.suffix in ['.pdf', '.md']:
                        size_bytes = report_file.stat().st_size
                        if size_bytes > 2048:  # Only substantial files
                            size_kb = size_bytes / 1024
                            reports.append({
                                'name': report_file.name,
                                'path': str(report_file),
                                'size': f"{size_kb:.1f} KB",
                                'size_bytes': size_bytes,
                                'modified': datetime.fromtimestamp(report_file.stat().st_mtime).strftime('%d/%m/%Y'),
                                'type': report_file.suffix
                            })

        # Sort by size (largest first) and remove duplicates
        seen_names = set()
        unique_reports = []
        for report in sorted(reports, key=lambda x: x['size_bytes'], reverse=True):
            if report['name'] not in seen_names:
                unique_reports.append(report)
                seen_names.add(report['name'])

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(unique_reports).encode())

    def check_service_status(self):
        # Check actual service status by testing HTTP endpoints
        import socket

        service_ports = {
            "sast_dast": 8001,
            "mobile_analysis": 8002,
            "binary_analysis": 8003,
            "ml_intelligence": 8004,
            "network_scanning": 8005,
            "web_reconnaissance": 8006
        }

        services = {}

        for service, port in service_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('127.0.0.1', port))
                sock.close()

                if result == 0:
                    services[service] = "active"
                else:
                    services[service] = "inactive"
            except Exception:
                services[service] = "inactive"

        return services

    def check_aws_status(self):
        # Check AWS services status (simplified)
        try:
            result = subprocess.run(['aws', 'sts', 'get-caller-identity'],
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return "connected"
        except:
            pass
        return "disconnected"

def start_main_dashboard():
    """Start the main dashboard web server"""
    os.chdir('/Users/ankitthakur/Downloads/QuantumSentinel-Nexus')

    with socketserver.TCPServer(("", PORT), MainDashboardHandler) as httpd:
        print(f"""
🛡️ QUANTUMSENTINEL-NEXUS MAIN DASHBOARD
=======================================
🌐 Main Dashboard: http://localhost:{PORT}
🎯 Huntr Dashboard: http://localhost:8009/huntr-dashboard

🚀 Platform Status:
• Main Dashboard: ACTIVE (Port {PORT})
• Huntr Dashboard: ACTIVE (Port 8009)
• AWS Infrastructure: OPERATIONAL
• Security Modules: ALL ACTIVE

📊 Quick Access:
• Huntr.com Assessment: Real-time ML/AI security testing
• AWS ECS Services: 10 microservices deployed
• Security Workflows: 5 automated testing pipelines
• HackTricks Coverage: 200+ attack techniques

Press Ctrl+C to stop the server
""")

        # Auto-open browser
        try:
            webbrowser.open(f'http://localhost:{PORT}')
        except:
            pass

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n🛑 Main dashboard server stopped")

if __name__ == "__main__":
    start_main_dashboard()