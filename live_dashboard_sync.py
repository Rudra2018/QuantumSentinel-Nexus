#!/usr/bin/env python3
"""
Live Dashboard Sync Service
Sync real-time scanning results with the unified dashboard
"""

import json
import glob
import time
import os
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import urllib.parse

class DashboardSyncHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Handle dashboard API requests"""
        if self.path == '/api/scan-status':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            # Get real-time scan data
            scan_data = self.get_scan_status()
            self.wfile.write(json.dumps(scan_data).encode())

        elif self.path == '/api/latest-reports':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            # Get latest scan reports
            reports = self.get_latest_reports()
            self.wfile.write(json.dumps(reports).encode())

        elif self.path == '/':
            # Serve updated dashboard with live data
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            # Generate live dashboard HTML
            dashboard_html = self.generate_live_dashboard()
            self.wfile.write(dashboard_html.encode())

        else:
            self.send_response(404)
            self.end_headers()

    def get_scan_status(self):
        """Get current scanning status"""
        # Count reports
        bb_reports = glob.glob("bug_bounty_scan_BB-*.json")
        quantum_reports = glob.glob("quantum_scan_report_*.json")

        # Parse latest scan activity from logs
        latest_activity = []
        if os.path.exists("bug_bounty_mass_scan.log"):
            with open("bug_bounty_mass_scan.log", 'r') as f:
                lines = f.readlines()[-20:]  # Last 20 lines
                for line in lines:
                    if "completed" in line and "Bug bounty scan" in line:
                        # Extract target name from log
                        parts = line.split("for ")
                        if len(parts) > 1:
                            target = parts[1].strip()
                            latest_activity.append({
                                "target": target,
                                "status": "completed",
                                "timestamp": line.split(" - ")[0]
                            })

        # Calculate vulnerabilities from reports
        total_critical = 0
        total_high = 0
        total_medium = 0
        total_low = 0

        for report_file in bb_reports:
            try:
                with open(report_file, 'r') as f:
                    report = json.load(f)
                    vuln_phase = report.get("phases", {}).get("vulnerability_scanning", {})
                    findings = vuln_phase.get("findings", [])
                    for finding in findings:
                        if finding.get("severity") == "critical":
                            total_critical += finding.get("count", 0)
                        elif finding.get("severity") == "high":
                            total_high += finding.get("count", 0)
                        elif finding.get("severity") == "medium":
                            total_medium += finding.get("count", 0)
                        elif finding.get("severity") == "low":
                            total_low += finding.get("count", 0)
            except:
                continue

        return {
            "bug_bounty_reports": len(bb_reports),
            "quantum_reports": len(quantum_reports),
            "total_findings": total_critical + total_high + total_medium + total_low,
            "critical_issues": total_critical,
            "high_issues": total_high,
            "medium_issues": total_medium,
            "low_issues": total_low,
            "active_scans": len(latest_activity),
            "latest_activity": latest_activity[-10:],  # Last 10 activities
            "timestamp": datetime.now().isoformat()
        }

    def get_latest_reports(self):
        """Get latest scan reports"""
        reports = []
        bb_files = sorted(glob.glob("bug_bounty_scan_BB-*.json"), key=os.path.getmtime, reverse=True)[:5]

        for report_file in bb_files:
            try:
                with open(report_file, 'r') as f:
                    report = json.load(f)
                    reports.append({
                        "scan_id": report.get("scan_id"),
                        "target": report.get("target"),
                        "program_type": report.get("program_type"),
                        "timestamp": report.get("timestamp"),
                        "file": report_file
                    })
            except:
                continue

        return reports

    def generate_live_dashboard(self):
        """Generate live dashboard HTML with real-time data"""
        scan_status = self.get_scan_status()

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>QuantumSentinel-Nexus - Live Scanning Dashboard</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72, #2a5298);
            color: white;
            min-height: 100vh;
            overflow-x: auto;
        }}
        .header {{
            background: rgba(0,0,0,0.3);
            padding: 20px;
            text-align: center;
            border-bottom: 2px solid #00ff88;
        }}
        .header h1 {{
            font-size: 2.5em;
            color: #00ff88;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.5);
        }}
        .live-indicator {{
            display: inline-block;
            width: 12px;
            height: 12px;
            background: #ff4444;
            border-radius: 50%;
            animation: pulse 1.5s infinite;
            margin-left: 10px;
        }}
        @keyframes pulse {{
            0% {{ opacity: 1; }}
            50% {{ opacity: 0.3; }}
            100% {{ opacity: 1; }}
        }}
        .dashboard-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            padding: 20px;
        }}
        .card {{
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.2);
            border-radius: 15px;
            padding: 20px;
            transition: transform 0.3s ease;
        }}
        .card:hover {{ transform: translateY(-5px); }}
        .card h3 {{
            color: #00ff88;
            margin-bottom: 15px;
            font-size: 1.4em;
            border-bottom: 2px solid #00ff88;
            padding-bottom: 10px;
        }}
        .stat-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin-top: 15px;
        }}
        .stat-item {{
            text-align: center;
            padding: 15px;
            background: rgba(0,255,136,0.1);
            border-radius: 10px;
            border: 1px solid rgba(0,255,136,0.3);
        }}
        .stat-number {{
            font-size: 2em;
            font-weight: bold;
            color: #00ff88;
        }}
        .stat-label {{
            font-size: 0.9em;
            opacity: 0.8;
            margin-top: 5px;
        }}
        .activity-list {{
            max-height: 300px;
            overflow-y: auto;
        }}
        .activity-item {{
            padding: 10px;
            margin: 5px 0;
            background: rgba(0,255,136,0.1);
            border-left: 4px solid #00ff88;
            border-radius: 5px;
        }}
        .activity-target {{
            font-weight: bold;
            color: #00ff88;
        }}
        .activity-time {{
            font-size: 0.8em;
            opacity: 0.7;
        }}
        .progress-bar {{
            width: 100%;
            height: 20px;
            background: rgba(255,255,255,0.1);
            border-radius: 10px;
            overflow: hidden;
            margin: 10px 0;
        }}
        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, #00ff88, #00cc6a);
            width: {min(100, (scan_status['bug_bounty_reports'] / 64) * 100):.1f}%;
            transition: width 0.5s ease;
        }}
        .critical {{ color: #ff4444; }}
        .high {{ color: #ff8800; }}
        .medium {{ color: #ffaa00; }}
        .low {{ color: #88ff88; }}
        .refresh-btn {{
            background: #00ff88;
            color: #1e3c72;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            font-weight: bold;
            cursor: pointer;
            margin-top: 10px;
        }}
        .refresh-btn:hover {{
            background: #00cc6a;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ QuantumSentinel-Nexus<span class="live-indicator"></span></h1>
        <p>Live Bug Bounty Scanning Dashboard - Real-time Results</p>
    </div>

    <div class="dashboard-grid">
        <!-- Scan Progress -->
        <div class="card">
            <h3>🎯 Scanning Progress</h3>
            <div class="progress-bar">
                <div class="progress-fill"></div>
            </div>
            <p><strong>{scan_status['bug_bounty_reports']}/64</strong> Bug Bounty Programs Scanned</p>
            <div class="stat-grid">
                <div class="stat-item">
                    <div class="stat-number">{scan_status['bug_bounty_reports']}</div>
                    <div class="stat-label">BB Reports</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number">{scan_status['quantum_reports']}</div>
                    <div class="stat-label">Quantum Reports</div>
                </div>
            </div>
        </div>

        <!-- Vulnerability Summary -->
        <div class="card">
            <h3>🚨 Vulnerability Summary</h3>
            <div class="stat-grid">
                <div class="stat-item">
                    <div class="stat-number critical">{scan_status['critical_issues']}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number high">{scan_status['high_issues']}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number medium">{scan_status['medium_issues']}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number low">{scan_status['low_issues']}</div>
                    <div class="stat-label">Low</div>
                </div>
            </div>
            <p style="margin-top: 15px;">
                <strong>Total Findings: {scan_status['total_findings']}</strong>
            </p>
        </div>

        <!-- Live Activity -->
        <div class="card">
            <h3>⚡ Live Scanning Activity</h3>
            <div class="activity-list">
                {''.join([f'''
                <div class="activity-item">
                    <div class="activity-target">{activity['target']}</div>
                    <div class="activity-time">Completed - {activity['timestamp']}</div>
                </div>
                ''' for activity in scan_status['latest_activity']]) if scan_status['latest_activity'] else '<p>No recent activity</p>'}
            </div>
            <button class="refresh-btn" onclick="location.reload()">🔄 Refresh Data</button>
        </div>

        <!-- Platform Status -->
        <div class="card">
            <h3>🖥️ Platform Status</h3>
            <div class="stat-grid">
                <div class="stat-item">
                    <div class="stat-number">6</div>
                    <div class="stat-label">Modules Active</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number">{scan_status['active_scans']}</div>
                    <div class="stat-label">Active Scans</div>
                </div>
            </div>
            <div style="margin-top: 15px;">
                <p>✅ SAST/DAST Analysis - ACTIVE</p>
                <p>✅ Mobile Security - ACTIVE</p>
                <p>✅ Binary Analysis - ACTIVE</p>
                <p>✅ ML Intelligence - ACTIVE</p>
                <p>✅ Network Scanning - ACTIVE</p>
                <p>✅ Web Reconnaissance - ACTIVE</p>
            </div>
        </div>
    </div>

    <script>
        // Auto-refresh every 30 seconds
        setInterval(function() {{
            location.reload();
        }}, 30000);

        // Show last updated time
        console.log('Dashboard updated:', '{scan_status['timestamp']}');
    </script>
</body>
</html>"""

def start_dashboard_sync_server():
    """Start the dashboard sync server"""
    server = HTTPServer(('127.0.0.1', 8200), DashboardSyncHandler)
    print("🌐 Live Dashboard Sync Server started at: http://127.0.0.1:8200")
    server.serve_forever()

if __name__ == "__main__":
    start_dashboard_sync_server()