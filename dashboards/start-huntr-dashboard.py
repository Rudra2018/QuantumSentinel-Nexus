#!/usr/bin/env python3
"""
Simple web server to serve the Huntr.com Security Assessment Dashboard
"""

import http.server
import socketserver
import webbrowser
import os
import json
from pathlib import Path

PORT = 8009

class HuntrHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/' or self.path == '/huntr-dashboard':
            # Serve the Huntr dashboard
            dashboard_path = Path('/Users/ankitthakur/Downloads/QuantumSentinel-Nexus/services/web-ui/huntr_dashboard.html')
            if dashboard_path.exists():
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                with open(dashboard_path, 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_error(404, "Dashboard not found")
        elif self.path == '/api/huntr/assessment-data':
            # Serve assessment data
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            # Load assessment data
            results_path = Path('/Users/ankitthakur/Downloads/QuantumSentinel-Nexus/results/huntr-assessment/huntr_comprehensive_assessment.json')
            if results_path.exists():
                with open(results_path, 'r') as f:
                    data = f.read()
                self.wfile.write(data.encode())
            else:
                # Return sample data
                sample_data = {
                    "assessment_metadata": {"total_targets": 10},
                    "summary_statistics": {"high_risk_targets": 2, "medium_risk_targets": 4, "low_risk_targets": 4}
                }
                self.wfile.write(json.dumps(sample_data).encode())
        else:
            super().do_GET()

def start_dashboard():
    """Start the Huntr dashboard web server"""
    os.chdir('/Users/ankitthakur/Downloads/QuantumSentinel-Nexus/services/web-ui')

    with socketserver.TCPServer(("", PORT), HuntrHandler) as httpd:
        print(f"""
🎯 HUNTR.COM SECURITY ASSESSMENT DASHBOARD
==========================================
🌐 Server started at: http://localhost:{PORT}
📊 Dashboard URL: http://localhost:{PORT}/huntr-dashboard

🚀 Features:
• Live assessment results
• Risk distribution charts
• Target prioritization matrix
• Attack vector analysis
• Real-time monitoring status

Press Ctrl+C to stop the server
""")

        # Auto-open browser
        try:
            webbrowser.open(f'http://localhost:{PORT}/huntr-dashboard')
        except:
            pass

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n🛑 Dashboard server stopped")

if __name__ == "__main__":
    start_dashboard()