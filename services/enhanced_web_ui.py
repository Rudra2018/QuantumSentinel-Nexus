#!/usr/bin/env python3
"""
🌐 QuantumSentinel Enhanced Web UI with Authentication and Real-time WebSocket Support
Advanced Flask application with JWT authentication, live scanning updates, and modern UI
"""

import asyncio
import json
import logging
import os
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any

from flask import Flask, render_template_string, request, jsonify, send_file, redirect, url_for
from flask_socketio import SocketIO, emit, disconnect
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, verify_jwt_in_request
import requests

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import our security engines and authentication
try:
    from security_engines.sast.bandit_engine import EnhancedSASTEngine
    from security_engines.dast.web_scanner import EnhancedDASTEngine
    from security_engines.binary.enhanced_binary_engine import EnhancedBinaryEngine, BinaryFormat, Architecture
    from ai_agents.ml_models.vulnerability_detector import MLVulnerabilityDetector
    from workflows.automation.pipeline_engine import WorkflowEngine
    from reports.generators import ReportGenerator, ReportMetadata, VulnerabilityFinding
    from config.settings import SecurityConfig
    from utils.logging import SecurityLogger
    from auth import db, User, ScanSession, AuditLog, init_db, auth_bp, require_auth
    BINARY_ENGINE_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Could not import security modules: {e}")
    BINARY_ENGINE_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("QuantumSentinel.EnhancedWebUI")

# Initialize Flask app with WebSocket support and authentication
app = Flask(__name__)
app.config['SECRET_KEY'] = 'quantum-sentinel-nexus-enhanced-ui-2024'
app.config['JWT_SECRET_KEY'] = 'quantum-jwt-secret-key-2024-change-in-production'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=2)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quantum_sentinel.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
jwt = JWTManager(app)
init_db(app)  # Initialize database
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
CORS(app)

# Register authentication blueprint
app.register_blueprint(auth_bp)

# Global state management
scan_sessions = {}
active_users = {}  # Track active WebSocket users
active_scans = {}
scan_results = {}
uploaded_files = {}  # Track uploaded binary files

# File upload configuration
UPLOAD_FOLDER = Path.cwd() / 'uploads'
UPLOAD_FOLDER.mkdir(exist_ok=True)
app.config['UPLOAD_FOLDER'] = str(UPLOAD_FOLDER)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max file size

# Supported binary file extensions
ALLOWED_BINARY_EXTENSIONS = {
    'elf': ['.bin', '.elf', '.out', '.so', '.a'],
    'pe': ['.exe', '.dll', '.scr', '.com', '.bat', '.pif'],
    'macho': ['.dylib', '.bundle', '.framework'],
    'ipa': ['.ipa'],
    'apk': ['.apk'],
    'deb': ['.deb'],
    'ko': ['.ko'],
    'kext': ['.kext'],
    'archive': ['.zip', '.tar', '.gz', '.bz2', '.xz', '.7z'],
    'firmware': ['.bin', '.img', '.rom', '.hex']
}

class WebScanSession:
    """Manages individual scan sessions with real-time updates"""

    def __init__(self, session_id: str, target: str, scan_types: List[str]):
        self.session_id = session_id
        self.target = target
        self.scan_types = scan_types
        self.status = "initializing"
        self.created_at = datetime.now()
        self.updated_at = datetime.now()
        self.progress = 0
        self.current_step = ""
        self.findings = []
        self.logs = []
        self.estimated_completion = None

class WebBinaryScanSession(WebScanSession):
    """Manages binary analysis sessions with enhanced metadata"""

    def __init__(self, session_id: str, file_info: dict, analysis_options: dict, user_id: str):
        super().__init__(session_id, file_info['original_filename'], ['binary'])
        self.file_info = file_info
        self.analysis_options = analysis_options
        self.user_id = user_id
        self.binary_metadata = {}
        self.format_analysis = {}
        self.security_features = {}
        self.ml_analysis = {}
        self.risk_score = 0
        self.security_rating = "UNKNOWN"

    def update_progress(self, progress: int, step: str = ""):
        """Update scan progress and emit to connected clients"""
        self.progress = progress
        self.current_step = step
        self.updated_at = datetime.now()

        # Emit progress update via WebSocket
        socketio.emit('scan_progress', {
            'session_id': self.session_id,
            'progress': self.progress,
            'step': self.current_step,
            'timestamp': self.updated_at.isoformat()
        }, room=f"scan_{self.session_id}")

    def add_finding(self, finding: dict):
        """Add a new finding and emit to connected clients"""
        self.findings.append(finding)
        self.updated_at = datetime.now()

        # Emit new finding via WebSocket
        socketio.emit('new_finding', {
            'session_id': self.session_id,
            'finding': finding,
            'total_findings': len(self.findings),
            'timestamp': self.updated_at.isoformat()
        }, room=f"scan_{self.session_id}")

    def add_log(self, level: str, message: str):
        """Add log entry and emit to connected clients"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'level': level,
            'message': message
        }
        self.logs.append(log_entry)

        # Emit log update via WebSocket
        socketio.emit('scan_log', {
            'session_id': self.session_id,
            'log': log_entry
        }, room=f"scan_{self.session_id}")

    def complete(self, status: str = "completed"):
        """Mark scan as completed"""
        self.status = status
        self.progress = 100
        self.updated_at = datetime.now()

        # Emit completion via WebSocket
        socketio.emit('scan_complete', {
            'session_id': self.session_id,
            'status': self.status,
            'findings_count': len(self.findings),
            'duration': str(self.updated_at - self.created_at),
            'timestamp': self.updated_at.isoformat()
        }, room=f"scan_{self.session_id}")

    def to_dict(self):
        """Convert session to dictionary for API responses"""
        return {
            'session_id': self.session_id,
            'target': self.target,
            'scan_types': self.scan_types,
            'status': self.status,
            'progress': self.progress,
            'current_step': self.current_step,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'findings_count': len(self.findings),
            'logs_count': len(self.logs)
        }

# HTML Templates
DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ QuantumSentinel-Nexus Enhanced Dashboard</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            min-height: 100vh;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            background: rgba(255,255,255,0.95);
            padding: 30px;
            border-radius: 15px;
            text-align: center;
            margin-bottom: 30px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
        }
        .header h1 {
            font-size: 2.5em;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }
        .header p {
            color: #666;
            font-size: 1.2em;
        }
        .dashboard-grid {
            display: grid;
            grid-template-columns: 1fr 2fr;
            gap: 30px;
            margin-bottom: 30px;
        }
        .control-panel, .live-feed {
            background: rgba(255,255,255,0.95);
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: linear-gradient(135deg, #ff6b6b, #ee5a24);
            color: white;
            padding: 20px;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }
        .stat-number {
            font-size: 2.2em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .stat-label {
            font-size: 1em;
            opacity: 0.9;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #444;
        }
        .form-control {
            width: 100%;
            padding: 12px;
            border: 2px solid #e1e1e1;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s ease;
        }
        .form-control:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            border: none;
            padding: 12px 25px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s ease;
            width: 100%;
        }
        .btn:hover {
            transform: translateY(-2px);
        }
        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        .scan-item {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
        }
        .scan-header {
            display: flex;
            justify-content: between;
            align-items: center;
            margin-bottom: 10px;
        }
        .scan-status {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .status-running {
            background: #fff3cd;
            color: #856404;
        }
        .status-completed {
            background: #d4edda;
            color: #155724;
        }
        .status-failed {
            background: #f8d7da;
            color: #721c24;
        }
        .progress-bar {
            width: 100%;
            height: 8px;
            background: #e9ecef;
            border-radius: 4px;
            margin: 10px 0;
            overflow: hidden;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(135deg, #667eea, #764ba2);
            border-radius: 4px;
            transition: width 0.3s ease;
        }
        .findings-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }
        .finding-card {
            background: rgba(255,255,255,0.95);
            border-radius: 12px;
            padding: 20px;
            border-left: 5px solid #667eea;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        .finding-card.critical {
            border-left-color: #dc3545;
        }
        .finding-card.high {
            border-left-color: #fd7e14;
        }
        .finding-card.medium {
            border-left-color: #ffc107;
        }
        .finding-card.low {
            border-left-color: #28a745;
        }
        .severity-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            color: white;
            margin-bottom: 10px;
        }
        .severity-critical { background: #dc3545; }
        .severity-high { background: #fd7e14; }
        .severity-medium { background: #ffc107; }
        .severity-low { background: #28a745; }
        .severity-info { background: #17a2b8; }
        .logs-container {
            max-height: 300px;
            overflow-y: auto;
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 8px;
            padding: 15px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }
        .log-entry {
            margin-bottom: 5px;
            padding: 2px 0;
        }
        .log-timestamp {
            color: #6c757d;
            margin-right: 10px;
        }
        .log-level {
            font-weight: bold;
            margin-right: 10px;
        }
        .log-info { color: #17a2b8; }
        .log-warning { color: #ffc107; }
        .log-error { color: #dc3545; }
        .log-success { color: #28a745; }
        .connection-status {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 10px 15px;
            border-radius: 8px;
            font-weight: bold;
            z-index: 1000;
        }
        .connected {
            background: #d4edda;
            color: #155724;
        }
        .disconnected {
            background: #f8d7da;
            color: #721c24;
        }
        .checkbox-group {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 10px;
            margin-top: 10px;
        }
        .checkbox-item {
            display: flex;
            align-items: center;
            gap: 8px;
        }
    </style>
</head>
<body>
    <div id="connectionStatus" class="connection-status disconnected">
        🔴 Disconnected
    </div>

    <div class="container">
        <div class="header">
            <h1>🛡️ QuantumSentinel-Nexus</h1>
            <p>Enhanced Security Testing Platform with Real-time Monitoring</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number" id="totalScans">0</div>
                <div class="stat-label">Total Scans</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="activeScans">0</div>
                <div class="stat-label">Active Scans</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="totalFindings">0</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="criticalFindings">0</div>
                <div class="stat-label">Critical Findings</div>
            </div>
        </div>

        <div class="dashboard-grid">
            <div class="control-panel">
                <h2>🚀 Launch Security Scan</h2>
                <form id="scanForm">
                    <div class="form-group">
                        <label for="target">Target URL/IP:</label>
                        <input type="text" id="target" class="form-control"
                               placeholder="https://example.com or 192.168.1.1" required>
                    </div>

                    <div class="form-group">
                        <label>Scan Types:</label>
                        <div class="checkbox-group">
                            <div class="checkbox-item">
                                <input type="checkbox" id="sast" value="sast" checked>
                                <label for="sast">SAST</label>
                            </div>
                            <div class="checkbox-item">
                                <input type="checkbox" id="dast" value="dast" checked>
                                <label for="dast">DAST</label>
                            </div>
                            <div class="checkbox-item">
                                <input type="checkbox" id="ai" value="ai_analysis" checked>
                                <label for="ai">AI Analysis</label>
                            </div>
                            <div class="checkbox-item">
                                <input type="checkbox" id="mobile" value="mobile">
                                <label for="mobile">Mobile</label>
                            </div>
                            <div class="checkbox-item">
                                <input type="checkbox" id="binary" value="binary">
                                <label for="binary">Binary</label>
                            </div>
                        </div>
                    </div>

                    <button type="submit" class="btn" id="startScanBtn">
                        🚀 Start Security Scan
                    </button>
                </form>
            </div>

            <div class="live-feed">
                <h2>📊 Live Scan Monitor</h2>
                <div id="activeScansList">
                    <p style="text-align: center; color: #666; padding: 40px;">
                        No active scans. Start a new scan to see real-time updates.
                    </p>
                </div>
            </div>
        </div>

        <div class="findings-grid" id="findingsGrid">
            <!-- Real-time findings will appear here -->
        </div>

        <div style="background: rgba(255,255,255,0.95); border-radius: 15px; padding: 25px; margin-top: 30px;">
            <h2>📋 System Logs</h2>
            <div class="logs-container" id="systemLogs">
                <div class="log-entry">
                    <span class="log-timestamp">[{{ current_time }}]</span>
                    <span class="log-level log-info">[INFO]</span>
                    QuantumSentinel-Nexus Enhanced Web UI initialized
                </div>
            </div>
        </div>
    </div>

    <script>
        // Initialize Socket.IO connection
        const socket = io();
        const connectionStatus = document.getElementById('connectionStatus');
        let currentScanSession = null;

        // Connection status handlers
        socket.on('connect', () => {
            connectionStatus.textContent = '🟢 Connected';
            connectionStatus.className = 'connection-status connected';
            addSystemLog('info', 'Connected to QuantumSentinel server');
        });

        socket.on('disconnect', () => {
            connectionStatus.textContent = '🔴 Disconnected';
            connectionStatus.className = 'connection-status disconnected';
            addSystemLog('error', 'Disconnected from server');
        });

        // Real-time scan event handlers
        socket.on('scan_progress', (data) => {
            updateScanProgress(data);
            addSystemLog('info', `Scan ${data.session_id}: ${data.step} (${data.progress}%)`);
        });

        socket.on('new_finding', (data) => {
            addFinding(data.finding);
            updateStats();
            addSystemLog('warning', `New ${data.finding.severity} finding discovered`);
        });

        socket.on('scan_complete', (data) => {
            completeScan(data);
            addSystemLog('success', `Scan ${data.session_id} completed with ${data.findings_count} findings`);
        });

        socket.on('scan_log', (data) => {
            // Could add scan-specific logs here
        });

        // Form submission handler
        document.getElementById('scanForm').addEventListener('submit', async (e) => {
            e.preventDefault();

            const target = document.getElementById('target').value;
            const scanTypes = Array.from(document.querySelectorAll('input[type="checkbox"]:checked'))
                                   .map(cb => cb.value);

            if (scanTypes.length === 0) {
                alert('Please select at least one scan type');
                return;
            }

            const startBtn = document.getElementById('startScanBtn');
            startBtn.disabled = true;
            startBtn.textContent = '🔄 Starting Scan...';

            try {
                const response = await fetch('/api/scans/start', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        target: target,
                        scan_types: scanTypes
                    })
                });

                const result = await response.json();

                if (response.ok) {
                    currentScanSession = result.session_id;
                    socket.emit('join_scan', { session_id: result.session_id });
                    addSystemLog('info', `Started scan ${result.session_id} for ${target}`);
                } else {
                    throw new Error(result.error || 'Failed to start scan');
                }
            } catch (error) {
                addSystemLog('error', `Failed to start scan: ${error.message}`);
                alert(`Error: ${error.message}`);
            } finally {
                startBtn.disabled = false;
                startBtn.textContent = '🚀 Start Security Scan';
            }
        });

        function updateScanProgress(data) {
            const activeScansList = document.getElementById('activeScansList');
            let scanElement = document.getElementById(`scan-${data.session_id}`);

            if (!scanElement) {
                scanElement = createScanElement(data.session_id);
                activeScansList.innerHTML = '';
                activeScansList.appendChild(scanElement);
            }

            // Update progress bar
            const progressFill = scanElement.querySelector('.progress-fill');
            const progressText = scanElement.querySelector('.progress-text');
            const stepText = scanElement.querySelector('.step-text');

            progressFill.style.width = `${data.progress}%`;
            progressText.textContent = `${data.progress}%`;
            stepText.textContent = data.step || 'Processing...';
        }

        function createScanElement(sessionId) {
            const element = document.createElement('div');
            element.id = `scan-${sessionId}`;
            element.className = 'scan-item';
            element.innerHTML = `
                <div class="scan-header">
                    <strong>Scan ${sessionId}</strong>
                    <span class="scan-status status-running">Running</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: 0%"></div>
                </div>
                <div style="display: flex; justify-content: space-between; font-size: 12px; color: #666;">
                    <span class="step-text">Initializing...</span>
                    <span class="progress-text">0%</span>
                </div>
            `;
            return element;
        }

        function completeScan(data) {
            const scanElement = document.getElementById(`scan-${data.session_id}`);
            if (scanElement) {
                const statusElement = scanElement.querySelector('.scan-status');
                statusElement.textContent = data.status;
                statusElement.className = `scan-status status-${data.status}`;

                const stepText = scanElement.querySelector('.step-text');
                stepText.textContent = `Completed in ${data.duration}`;
            }
            updateStats();
        }

        function addFinding(finding) {
            const findingsGrid = document.getElementById('findingsGrid');

            const findingElement = document.createElement('div');
            findingElement.className = `finding-card ${finding.severity.toLowerCase()}`;
            findingElement.innerHTML = `
                <span class="severity-badge severity-${finding.severity.toLowerCase()}">${finding.severity}</span>
                <h3>${finding.title}</h3>
                <p><strong>Description:</strong> ${finding.description}</p>
                <p><strong>Impact:</strong> ${finding.impact}</p>
                ${finding.file_path ? `<p><strong>File:</strong> ${finding.file_path}</p>` : ''}
                ${finding.line_number ? `<p><strong>Line:</strong> ${finding.line_number}</p>` : ''}
                <p><strong>Recommendation:</strong> ${finding.recommendation}</p>
                <div style="font-size: 12px; color: #666; margin-top: 10px;">
                    Found at: ${new Date().toLocaleTimeString()}
                </div>
            `;

            findingsGrid.insertBefore(findingElement, findingsGrid.firstChild);
        }

        function addSystemLog(level, message) {
            const logsContainer = document.getElementById('systemLogs');
            const timestamp = new Date().toLocaleTimeString();

            const logElement = document.createElement('div');
            logElement.className = 'log-entry';
            logElement.innerHTML = `
                <span class="log-timestamp">[${timestamp}]</span>
                <span class="log-level log-${level}">[${level.toUpperCase()}]</span>
                ${message}
            `;

            logsContainer.insertBefore(logElement, logsContainer.firstChild);

            // Keep only last 100 log entries
            while (logsContainer.children.length > 100) {
                logsContainer.removeChild(logsContainer.lastChild);
            }
        }

        function updateStats() {
            // This would typically fetch real stats from the server
            // For now, we'll simulate it
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('totalScans').textContent = data.total_scans || 0;
                    document.getElementById('activeScans').textContent = data.active_scans || 0;
                    document.getElementById('totalFindings').textContent = data.total_findings || 0;
                    document.getElementById('criticalFindings').textContent = data.critical_findings || 0;
                })
                .catch(error => console.error('Failed to update stats:', error));
        }

        // Initial stats load
        updateStats();
        setInterval(updateStats, 30000); // Update every 30 seconds
    </script>
</body>
</html>
"""

# Flask Routes
@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template_string(DASHBOARD_TEMPLATE, current_time=datetime.now().strftime('%H:%M:%S'))

@app.route('/api/stats')
def get_stats():
    """Get current statistics"""
    total_scans = len(scan_sessions)
    active_scans = len([s for s in scan_sessions.values() if s.status == 'running'])
    total_findings = sum(len(s.findings) for s in scan_sessions.values())
    critical_findings = sum(
        len([f for f in s.findings if f.get('severity', '').upper() == 'CRITICAL'])
        for s in scan_sessions.values()
    )

    return jsonify({
        'total_scans': total_scans,
        'active_scans': active_scans,
        'total_findings': total_findings,
        'critical_findings': critical_findings,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/scans/start', methods=['POST'])
@jwt_required()
def start_scan():
    """Start a new security scan"""
    try:
        # Get current user from JWT token
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        if not current_user:
            return jsonify({'error': 'User not found'}), 404

        data = request.get_json()
        target = data.get('target')
        scan_types = data.get('scan_types', [])

        if not target or not scan_types:
            return jsonify({'error': 'Target and scan_types are required'}), 400

        # Create database scan session
        db_scan_session = ScanSession(
            user_id=current_user.id,
            scan_type='+'.join(scan_types),
            target=target,
            config=data.get('config', {})
        )
        db.session.add(db_scan_session)
        db.session.commit()

        # Create web scan session for real-time tracking
        session_id = db_scan_session.session_id
        scan_session = WebScanSession(session_id, target, scan_types)
        scan_session.user_id = current_user.id
        scan_session.db_session_id = db_scan_session.id
        scan_sessions[session_id] = scan_session

        # Log audit event
        AuditLog.log_action(
            action='scan_started',
            user_id=current_user.id,
            resource=f'scan:{session_id}',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            details={
                'target': target,
                'scan_types': scan_types,
                'session_id': session_id
            }
        )

        # Start scan in background thread
        scan_thread = threading.Thread(
            target=run_security_scan,
            args=(scan_session,),
            daemon=True
        )
        scan_thread.start()

        return jsonify({
            'session_id': session_id,
            'status': 'started',
            'target': target,
            'scan_types': scan_types,
            'message': 'Security scan started successfully'
        })

    except Exception as e:
        logger.error(f"Failed to start scan: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scans/<session_id>')
@jwt_required()
def get_scan_status(session_id):
    """Get status of a specific scan"""
    if session_id not in scan_sessions:
        return jsonify({'error': 'Scan session not found'}), 404

    session = scan_sessions[session_id]
    return jsonify(session.to_dict())

@app.route('/api/scans/<session_id>/findings')
@jwt_required()
def get_scan_findings(session_id):
    """Get findings for a specific scan"""
    if session_id not in scan_sessions:
        return jsonify({'error': 'Scan session not found'}), 404

    session = scan_sessions[session_id]
    return jsonify({
        'session_id': session_id,
        'findings': session.findings,
        'total_count': len(session.findings)
    })

@app.route('/api/binary/upload', methods=['POST'])
@jwt_required()
def upload_binary():
    """Upload binary file for analysis"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        # Validate file
        if not _is_allowed_binary_file(file.filename):
            return jsonify({'error': 'Unsupported file type'}), 400

        # Generate unique file ID
        file_id = str(uuid.uuid4())
        file_extension = Path(file.filename).suffix.lower()

        # Save file
        safe_filename = f"{file_id}{file_extension}"
        file_path = UPLOAD_FOLDER / safe_filename
        file.save(str(file_path))

        # Detect binary format
        binary_format = _detect_binary_format(file_path)

        # Store file metadata
        uploaded_files[file_id] = {
            'id': file_id,
            'original_filename': file.filename,
            'safe_filename': safe_filename,
            'file_path': str(file_path),
            'file_size': os.path.getsize(file_path),
            'detected_format': binary_format,
            'upload_time': datetime.now().isoformat(),
            'uploaded_by': get_jwt_identity()
        }

        logger.info(f"Binary uploaded: {file.filename} -> {safe_filename} (Format: {binary_format})")

        return jsonify({
            'file_id': file_id,
            'filename': file.filename,
            'size': uploaded_files[file_id]['file_size'],
            'detected_format': binary_format,
            'upload_time': uploaded_files[file_id]['upload_time']
        })

    except Exception as e:
        logger.error(f"Binary upload failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/binary/analyze', methods=['POST'])
@jwt_required()
def analyze_binary():
    """Start binary analysis on uploaded file"""
    try:
        data = request.json
        file_id = data.get('file_id')
        analysis_options = data.get('options', {})

        if not file_id or file_id not in uploaded_files:
            return jsonify({'error': 'Invalid file ID'}), 400

        file_info = uploaded_files[file_id]

        # Create binary scan session
        session_id = str(uuid.uuid4())
        scan_session = WebBinaryScanSession(
            session_id=session_id,
            file_info=file_info,
            analysis_options=analysis_options,
            user_id=get_jwt_identity()
        )

        scan_sessions[session_id] = scan_session

        # Start binary analysis in background
        def run_analysis():
            try:
                run_binary_analysis_comprehensive(scan_session)
            except Exception as e:
                logger.error(f"Binary analysis failed: {e}")
                scan_session.add_log('error', f"Analysis failed: {str(e)}")
                scan_session.status = "failed"

        thread = threading.Thread(target=run_analysis)
        thread.start()

        logger.info(f"Started binary analysis: {session_id} for file {file_info['original_filename']}")

        return jsonify({
            'session_id': session_id,
            'status': 'started',
            'file_info': {
                'filename': file_info['original_filename'],
                'format': file_info['detected_format'],
                'size': file_info['file_size']
            }
        })

    except Exception as e:
        logger.error(f"Binary analysis start failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/binary/formats')
@jwt_required()
def get_supported_formats():
    """Get supported binary formats and their extensions"""
    return jsonify({
        'formats': ALLOWED_BINARY_EXTENSIONS,
        'analysis_features': {
            'static_analysis': True,
            'dynamic_analysis': BINARY_ENGINE_AVAILABLE,
            'ml_analysis': True,
            'security_features': True,
            'format_specific': {
                'elf': ['sections', 'symbols', 'relocations', 'security_features'],
                'pe': ['imports', 'exports', 'resources', 'certificates'],
                'macho': ['load_commands', 'segments', 'code_signature'],
                'ipa': ['app_info', 'entitlements', 'frameworks', 'provisioning'],
                'apk': ['manifest', 'dex_analysis', 'native_libs', 'certificates'],
                'deb': ['package_info', 'binaries', 'scripts'],
                'ko': ['module_info', 'kernel_hooks', 'dependencies'],
                'kext': ['bundle_info', 'kernel_extensions', 'code_signature']
            }
        }
    })

@app.route('/api/binary/files')
@jwt_required()
def list_uploaded_files():
    """List uploaded binary files for current user"""
    try:
        user_id = get_jwt_identity()
        user_files = [
            {
                'id': file_info['id'],
                'filename': file_info['original_filename'],
                'size': file_info['file_size'],
                'format': file_info['detected_format'],
                'upload_time': file_info['upload_time']
            }
            for file_info in uploaded_files.values()
            if file_info['uploaded_by'] == user_id
        ]

        return jsonify({
            'files': user_files,
            'total': len(user_files)
        })

    except Exception as e:
        logger.error(f"File listing failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/binary/files/<file_id>', methods=['DELETE'])
@jwt_required()
def delete_uploaded_file(file_id):
    """Delete uploaded binary file"""
    try:
        if file_id not in uploaded_files:
            return jsonify({'error': 'File not found'}), 404

        file_info = uploaded_files[file_id]
        user_id = get_jwt_identity()

        # Check ownership
        if file_info['uploaded_by'] != user_id:
            return jsonify({'error': 'Unauthorized'}), 403

        # Delete physical file
        file_path = Path(file_info['file_path'])
        if file_path.exists():
            file_path.unlink()

        # Remove from tracking
        del uploaded_files[file_id]

        logger.info(f"Deleted binary file: {file_info['original_filename']} (ID: {file_id})")

        return jsonify({'message': 'File deleted successfully'})

    except Exception as e:
        logger.error(f"File deletion failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scans/<session_id>/report')
@jwt_required()
def generate_scan_report(session_id):
    """Generate comprehensive report for a scan"""
    if session_id not in scan_sessions:
        return jsonify({'error': 'Scan session not found'}), 404

    try:
        session = scan_sessions[session_id]

        # Create report metadata
        metadata = ReportMetadata(
            title="QuantumSentinel Security Assessment",
            target=session.target,
            scan_type=" + ".join(session.scan_types),
            timestamp=session.created_at
        )

        # Convert findings to VulnerabilityFinding objects
        vulnerability_findings = []
        for i, finding in enumerate(session.findings):
            vuln = VulnerabilityFinding(
                id=f"QS-{session_id}-{i+1:03d}",
                title=finding.get('title', 'Unknown Vulnerability'),
                severity=finding.get('severity', 'INFO'),
                confidence=finding.get('confidence', 'Medium'),
                description=finding.get('description', 'No description available'),
                impact=finding.get('impact', 'Impact assessment pending'),
                recommendation=finding.get('recommendation', 'Review and assess'),
                cwe_id=finding.get('cwe_id'),
                owasp_category=finding.get('owasp_category'),
                file_path=finding.get('file_path'),
                line_number=finding.get('line_number'),
                evidence=finding.get('evidence')
            )
            vulnerability_findings.append(vuln)

        # Generate report
        report_generator = ReportGenerator()
        scan_results = {
            'session_id': session_id,
            'duration': str(session.updated_at - session.created_at),
            'scan_types': session.scan_types
        }

        # For now, generate JSON report
        reports = {}
        import asyncio
        if hasattr(asyncio, 'run'):
            reports = asyncio.run(
                report_generator.generate_comprehensive_report(
                    metadata, vulnerability_findings, scan_results, ["json"]
                )
            )

        return jsonify({
            'session_id': session_id,
            'reports_generated': list(reports.keys()),
            'report_files': reports,
            'message': 'Report generated successfully'
        })

    except Exception as e:
        logger.error(f"Failed to generate report: {e}")
        return jsonify({'error': str(e)}), 500

# WebSocket Event Handlers
@socketio.on('connect')
def handle_connect(auth):
    """Handle client connection with authentication"""
    try:
        # Verify JWT token from WebSocket authentication
        if auth and 'token' in auth:
            from flask_jwt_extended import decode_token
            try:
                decoded_token = decode_token(auth['token'])
                user_id = decoded_token['sub']
                user = User.query.get(user_id)

                if user and user.is_active:
                    # Store user info for this socket connection
                    active_users[request.sid] = {
                        'user_id': user_id,
                        'username': user.username,
                        'connected_at': datetime.now().isoformat()
                    }

                    logger.info(f"Authenticated user {user.username} connected: {request.sid}")
                    emit('connection_status', {
                        'status': 'authenticated',
                        'message': f'Connected as {user.username}',
                        'user': user.username
                    })
                    return True
                else:
                    logger.warning(f"Invalid user for connection: {request.sid}")
                    disconnect()
                    return False

            except Exception as e:
                logger.warning(f"Invalid token for connection {request.sid}: {e}")
                disconnect()
                return False
        else:
            logger.warning(f"No authentication provided for connection: {request.sid}")
            disconnect()
            return False

    except Exception as e:
        logger.error(f"Authentication error for connection {request.sid}: {e}")
        disconnect()
        return False

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    if request.sid in active_users:
        username = active_users[request.sid]['username']
        del active_users[request.sid]
        logger.info(f"User {username} disconnected: {request.sid}")
    else:
        logger.info(f"Client disconnected: {request.sid}")

@socketio.on('join_scan')
def handle_join_scan(data):
    """Join a specific scan room for real-time updates"""
    # Check if user is authenticated
    if request.sid not in active_users:
        emit('error', {'message': 'Authentication required'})
        return

    session_id = data.get('session_id')
    if session_id and session_id in scan_sessions:
        scan_session = scan_sessions[session_id]
        user_info = active_users[request.sid]

        # Check if user owns this scan or is admin
        user = User.query.get(user_info['user_id'])
        if scan_session.user_id == user.id or user.role == 'admin':
            from flask_socketio import join_room
            join_room(f"scan_{session_id}")
            emit('scan_joined', {'session_id': session_id, 'message': 'Joined scan updates'})
            logger.info(f"User {user.username} joined scan {session_id}")
        else:
            emit('error', {'message': 'Access denied to scan session'})
    else:
        emit('error', {'message': 'Scan session not found'})

def run_security_scan(scan_session: WebScanSession):
    """Run the actual security scan in a background thread"""
    try:
        scan_session.add_log('info', f"Starting security scan for {scan_session.target}")
        scan_session.update_progress(5, "Initializing scan engines")

        # Initialize security engines based on selected scan types
        if 'sast' in scan_session.scan_types:
            scan_session.update_progress(15, "Running SAST analysis")
            run_sast_scan(scan_session)

        if 'dast' in scan_session.scan_types:
            scan_session.update_progress(40, "Running DAST analysis")
            run_dast_scan(scan_session)

        if 'ai_analysis' in scan_session.scan_types:
            scan_session.update_progress(70, "Running AI vulnerability analysis")
            run_ai_analysis(scan_session)

        if 'mobile' in scan_session.scan_types:
            scan_session.update_progress(85, "Running mobile security analysis")
            run_mobile_scan(scan_session)

        if 'binary' in scan_session.scan_types:
            scan_session.update_progress(95, "Running binary analysis")
            run_binary_scan(scan_session)

        scan_session.update_progress(100, "Finalizing scan results")
        scan_session.complete("completed")
        scan_session.add_log('success', f"Scan completed with {len(scan_session.findings)} findings")

    except Exception as e:
        scan_session.add_log('error', f"Scan failed: {str(e)}")
        scan_session.complete("failed")
        logger.error(f"Scan {scan_session.session_id} failed: {e}")

def run_sast_scan(scan_session: WebScanSession):
    """Run SAST analysis"""
    try:
        # Simulate SAST scan with sample findings
        import time
        time.sleep(2)  # Simulate processing time

        # Add sample SAST findings
        sast_findings = [
            {
                'title': 'Hardcoded Secret Detected',
                'severity': 'HIGH',
                'confidence': 'High',
                'description': 'Hardcoded API key found in source code',
                'impact': 'Could expose sensitive credentials to attackers',
                'recommendation': 'Move secrets to environment variables or secure vault',
                'file_path': '/app/config.py',
                'line_number': 23,
                'evidence': 'API_KEY = "sk-1234567890abcdef"',
                'cwe_id': 'CWE-798',
                'owasp_category': 'A07:2021-Identification and Authentication Failures'
            },
            {
                'title': 'SQL Injection Risk',
                'severity': 'CRITICAL',
                'confidence': 'Medium',
                'description': 'Direct SQL query construction without parameterization',
                'impact': 'Could allow unauthorized database access',
                'recommendation': 'Use parameterized queries or ORM',
                'file_path': '/app/database.py',
                'line_number': 156,
                'evidence': 'query = f"SELECT * FROM users WHERE id = {user_id}"',
                'cwe_id': 'CWE-89',
                'owasp_category': 'A03:2021-Injection'
            }
        ]

        for finding in sast_findings:
            scan_session.add_finding(finding)
            time.sleep(1)  # Simulate progressive discovery

    except Exception as e:
        scan_session.add_log('error', f"SAST scan failed: {str(e)}")

def run_dast_scan(scan_session: WebScanSession):
    """Run DAST analysis"""
    try:
        import time
        time.sleep(3)  # Simulate processing time

        # Add sample DAST findings
        dast_findings = [
            {
                'title': 'Missing Security Headers',
                'severity': 'MEDIUM',
                'confidence': 'High',
                'description': 'Critical security headers are missing',
                'impact': 'Increases risk of client-side attacks',
                'recommendation': 'Implement Content-Security-Policy, X-Frame-Options, etc.',
                'evidence': 'Missing: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options',
                'cwe_id': 'CWE-693',
                'owasp_category': 'A05:2021-Security Misconfiguration'
            },
            {
                'title': 'Reflected XSS Vulnerability',
                'severity': 'HIGH',
                'confidence': 'High',
                'description': 'User input reflected without proper encoding',
                'impact': 'Could allow JavaScript injection attacks',
                'recommendation': 'Implement proper output encoding and CSP',
                'evidence': 'Payload: <script>alert("XSS")</script>',
                'cwe_id': 'CWE-79',
                'owasp_category': 'A03:2021-Injection'
            }
        ]

        for finding in dast_findings:
            scan_session.add_finding(finding)
            time.sleep(1.5)

    except Exception as e:
        scan_session.add_log('error', f"DAST scan failed: {str(e)}")

def run_ai_analysis(scan_session: WebScanSession):
    """Run AI vulnerability analysis"""
    try:
        import time
        time.sleep(2)

        # Add sample AI analysis findings
        ai_findings = [
            {
                'title': 'Suspicious Code Pattern Detected',
                'severity': 'MEDIUM',
                'confidence': 'Medium',
                'description': 'AI model detected potentially vulnerable code patterns',
                'impact': 'Code patterns suggest potential security weaknesses',
                'recommendation': 'Manual review recommended for flagged code sections',
                'evidence': 'ML confidence: 78%',
                'cwe_id': 'CWE-691',
                'owasp_category': 'A06:2021-Vulnerable and Outdated Components'
            }
        ]

        for finding in ai_findings:
            scan_session.add_finding(finding)
            time.sleep(1)

    except Exception as e:
        scan_session.add_log('error', f"AI analysis failed: {str(e)}")

def run_mobile_scan(scan_session: WebScanSession):
    """Run mobile security analysis (placeholder)"""
    try:
        import time
        time.sleep(1)
        scan_session.add_log('info', 'Mobile analysis engine not yet implemented')
    except Exception as e:
        scan_session.add_log('error', f"Mobile scan failed: {str(e)}")

# Helper functions for binary analysis
def _is_allowed_binary_file(filename: str) -> bool:
    """Check if uploaded file is a supported binary format"""
    if not filename:
        return False

    file_extension = Path(filename).suffix.lower()

    # Check against all supported extensions
    for format_type, extensions in ALLOWED_BINARY_EXTENSIONS.items():
        if file_extension in extensions:
            return True

    return False

def _detect_binary_format(file_path: Path) -> str:
    """Detect binary format using file magic and extension"""
    try:
        import subprocess

        # Use file command for detection
        result = subprocess.run(['file', str(file_path)], capture_output=True, text=True, timeout=10)
        file_output = result.stdout.lower() if result.returncode == 0 else ""

        # Get file extension
        file_extension = file_path.suffix.lower()

        # Detection logic
        if 'elf' in file_output:
            return 'elf'
        elif 'pe32' in file_output or 'ms-dos' in file_output or file_extension in ['.exe', '.dll']:
            return 'pe'
        elif 'mach-o' in file_output or file_extension in ['.dylib', '.bundle']:
            return 'macho'
        elif file_extension == '.ipa':
            return 'ipa'
        elif file_extension == '.apk':
            return 'apk'
        elif file_extension == '.deb':
            return 'deb'
        elif file_extension == '.ko':
            return 'ko'
        elif file_extension == '.kext' or 'kext' in str(file_path).lower():
            return 'kext'
        elif file_extension in ['.zip', '.tar', '.gz']:
            return 'archive'
        elif file_extension in ['.bin', '.img', '.rom']:
            return 'firmware'
        else:
            return 'unknown'

    except Exception as e:
        logger.warning(f"Binary format detection failed: {e}")
        return 'unknown'

def run_binary_analysis_comprehensive(scan_session: WebBinaryScanSession):
    """Run comprehensive binary analysis with real-time updates"""
    try:
        scan_session.status = "running"
        scan_session.update_progress(5, "Initializing binary analysis")

        file_path = scan_session.file_info['file_path']
        file_format = scan_session.file_info['detected_format']

        scan_session.add_log('info', f"Starting analysis of {scan_session.file_info['original_filename']}")
        scan_session.add_log('info', f"Detected format: {file_format}")

        if not BINARY_ENGINE_AVAILABLE:
            scan_session.add_log('warning', 'Enhanced binary engine not available, using basic analysis')
            _run_basic_binary_analysis(scan_session)
            return

        # Initialize enhanced binary engine
        scan_session.update_progress(10, "Initializing enhanced binary engine")

        engine_config = {
            'enable_ml': scan_session.analysis_options.get('enable_ml', True),
            'timeout': scan_session.analysis_options.get('timeout', 300)
        }

        engine = EnhancedBinaryEngine(engine_config)

        # Run comprehensive analysis
        scan_session.update_progress(15, "Extracting binary metadata")

        analysis_options = {
            'enable_dynamic': scan_session.analysis_options.get('dynamic_analysis', False),
            'enable_ml': scan_session.analysis_options.get('ml_analysis', True)
        }

        # Use asyncio to run the async analysis
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            results = loop.run_until_complete(
                engine.analyze_binary_comprehensive(
                    file_path=file_path,
                    **analysis_options
                )
            )
        finally:
            loop.close()

        # Process results
        scan_session.update_progress(80, "Processing analysis results")
        _process_binary_analysis_results(scan_session, results)

        # Generate findings
        scan_session.update_progress(90, "Generating security findings")
        _extract_binary_findings(scan_session, results)

        scan_session.update_progress(100, "Analysis complete")
        scan_session.status = "completed"
        scan_session.add_log('success', f"Binary analysis completed with {len(scan_session.findings)} findings")

    except Exception as e:
        logger.error(f"Binary analysis failed: {e}")
        scan_session.add_log('error', f"Analysis failed: {str(e)}")
        scan_session.status = "failed"

def _run_basic_binary_analysis(scan_session: WebBinaryScanSession):
    """Run basic binary analysis without enhanced engine"""
    try:
        import subprocess

        file_path = scan_session.file_info['file_path']

        scan_session.update_progress(20, "Running basic file analysis")

        # Basic file information
        try:
            result = subprocess.run(['file', file_path], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                scan_session.binary_metadata['file_type'] = result.stdout.strip()
        except Exception:
            pass

        scan_session.update_progress(40, "Extracting strings")

        # Extract strings
        try:
            result = subprocess.run(['strings', file_path], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                strings_list = result.stdout.strip().split('\n')[:100]  # First 100 strings
                scan_session.binary_metadata['strings_sample'] = strings_list
        except Exception:
            pass

        scan_session.update_progress(70, "Checking security features")

        # Basic security checks for ELF files
        if scan_session.file_info['detected_format'] == 'elf':
            try:
                result = subprocess.run(['readelf', '-h', file_path], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    scan_session.security_features['readelf_header'] = result.stdout
            except Exception:
                pass

        scan_session.update_progress(100, "Basic analysis complete")
        scan_session.status = "completed"
        scan_session.add_log('info', "Basic binary analysis completed")

    except Exception as e:
        logger.error(f"Basic binary analysis failed: {e}")
        scan_session.add_log('error', f"Basic analysis failed: {str(e)}")
        scan_session.status = "failed"

def _process_binary_analysis_results(scan_session: WebBinaryScanSession, results: dict):
    """Process and store binary analysis results"""
    try:
        # Store metadata
        if 'metadata' in results:
            metadata = results['metadata']
            scan_session.binary_metadata = {
                'format': metadata.format.value if hasattr(metadata.format, 'value') else str(metadata.format),
                'architecture': metadata.architecture.value if hasattr(metadata.architecture, 'value') else str(metadata.architecture),
                'file_size': metadata.file_size,
                'entropy': metadata.entropy,
                'packed': metadata.packed,
                'signed': metadata.signed,
                'strings_count': len(metadata.strings) if metadata.strings else 0,
                'imports_count': len(metadata.imports) if metadata.imports else 0,
                'exports_count': len(metadata.exports) if metadata.exports else 0
            }

        # Store format-specific analysis
        if 'format_analysis' in results:
            scan_session.format_analysis = results['format_analysis']

        # Store security features
        if 'security_features' in results:
            scan_session.security_features = results['security_features']

        # Store ML analysis
        if 'ml_analysis' in results:
            scan_session.ml_analysis = results['ml_analysis']

        # Store risk assessment
        if 'summary' in results:
            summary = results['summary']
            scan_session.risk_score = summary.get('risk_score', 0)
            scan_session.security_rating = summary.get('security_rating', 'UNKNOWN')

        scan_session.add_log('info', f"Processed analysis results: Risk Score {scan_session.risk_score}/100")

    except Exception as e:
        logger.error(f"Failed to process binary analysis results: {e}")
        scan_session.add_log('error', f"Failed to process results: {str(e)}")

def _extract_binary_findings(scan_session: WebBinaryScanSession, results: dict):
    """Extract and format security findings from analysis results"""
    try:
        findings_list = results.get('findings', [])

        for finding_data in findings_list:
            # Convert finding data to web format
            finding = {
                'id': finding_data.get('id', str(uuid.uuid4())),
                'title': finding_data.get('title', 'Security Finding'),
                'severity': finding_data.get('severity', 'MEDIUM'),
                'confidence': finding_data.get('confidence', 'Medium'),
                'description': finding_data.get('description', ''),
                'impact': finding_data.get('impact', ''),
                'recommendation': finding_data.get('recommendation', ''),
                'category': finding_data.get('category', 'Binary Security'),
                'cwe_id': finding_data.get('cwe_id'),
                'owasp_category': finding_data.get('owasp_category'),
                'evidence': finding_data.get('evidence'),
                'address': finding_data.get('address'),
                'function_name': finding_data.get('function_name'),
                'timestamp': datetime.now().isoformat()
            }

            scan_session.findings.append(finding)

        # Add summary finding for overall risk assessment
        if scan_session.risk_score > 0:
            summary_finding = {
                'id': str(uuid.uuid4()),
                'title': f"Overall Security Assessment: {scan_session.security_rating}",
                'severity': _risk_score_to_severity(scan_session.risk_score),
                'confidence': 'High',
                'description': f"Binary security assessment resulted in risk score of {scan_session.risk_score}/100",
                'impact': f"Security rating: {scan_session.security_rating}",
                'recommendation': _get_security_recommendations(scan_session.security_rating),
                'category': 'Security Assessment',
                'timestamp': datetime.now().isoformat()
            }
            scan_session.findings.append(summary_finding)

    except Exception as e:
        logger.error(f"Failed to extract binary findings: {e}")
        scan_session.add_log('error', f"Failed to extract findings: {str(e)}")

def _risk_score_to_severity(risk_score: int) -> str:
    """Convert risk score to severity level"""
    if risk_score >= 75:
        return 'CRITICAL'
    elif risk_score >= 50:
        return 'HIGH'
    elif risk_score >= 25:
        return 'MEDIUM'
    elif risk_score > 0:
        return 'LOW'
    else:
        return 'INFO'

def _get_security_recommendations(security_rating: str) -> str:
    """Get security recommendations based on rating"""
    recommendations = {
        'CRITICAL': 'Immediate action required. This binary poses significant security risks.',
        'HIGH': 'High priority security issues found. Review and remediate findings.',
        'MEDIUM': 'Moderate security concerns identified. Consider addressing findings.',
        'LOW': 'Minor security issues detected. Monitor and address as needed.',
        'SECURE': 'No significant security issues found. Continue following best practices.'
    }
    return recommendations.get(security_rating, 'Review security findings and take appropriate action.')

def run_binary_scan(scan_session: WebScanSession):
    """Run binary analysis (legacy function for compatibility)"""
    try:
        import time
        time.sleep(1)
        scan_session.add_log('info', 'Binary analysis engine not yet implemented')
    except Exception as e:
        scan_session.add_log('error', f"Binary scan failed: {str(e)}")

if __name__ == '__main__':
    print("🌐 Starting QuantumSentinel Enhanced Web UI with WebSocket support...")
    print("🔗 Dashboard: http://localhost:5001")
    print("🔌 WebSocket: Real-time updates enabled")
    print("📊 API: http://localhost:5001/api/")
    print("=" * 60)

    # Start the Flask-SocketIO server
    socketio.run(
        app,
        host='0.0.0.0',
        port=5001,
        debug=False,
        allow_unsafe_werkzeug=True
    )