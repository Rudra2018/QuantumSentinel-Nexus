#!/usr/bin/env python3
"""
Simple Huntr dashboard test to debug port issues
"""

import http.server
import socketserver
import json
from datetime import datetime

PORT = 8151  # Different port to avoid conflicts

class SimpleHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_simple_page()
        elif self.path == '/api/test':
            self.send_test_api()
        else:
            self.send_404()

    def do_POST(self):
        if self.path == '/api/huntr/launch':
            self.handle_launch()
        else:
            self.send_404()

    def send_simple_page(self):
        html = """
<!DOCTYPE html>
<html>
<head>
    <title>🎯 Huntr Test Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #1a1a2e; color: #e0e0e0; }
        .btn { background: #ff6b6b; color: white; border: none; padding: 15px 25px;
               border-radius: 5px; cursor: pointer; margin: 10px; font-size: 16px; }
        .btn:hover { background: #ee5a24; }
        .result { margin: 20px 0; padding: 15px; background: rgba(255,255,255,0.1);
                  border-radius: 5px; }
    </style>
</head>
<body>
    <h1>🎯 Huntr Bug Bounty Test Dashboard</h1>
    <p>Testing simplified version to debug issues</p>

    <button class="btn" onclick="launchTest()">🚀 Launch Huntr Assessment</button>
    <button class="btn" onclick="viewDashboard()">📊 View Huntr Dashboard</button>

    <div id="result" class="result"></div>

    <script>
        function launchTest() {
            fetch('/api/huntr/launch', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    document.getElementById('result').innerHTML =
                        '✅ Launch Success!<br>Scan ID: ' + data.scan_id + '<br>Status: ' + data.status;
                })
                .catch(error => {
                    document.getElementById('result').innerHTML = '❌ Launch Failed: ' + error;
                });
        }

        function viewDashboard() {
            document.getElementById('result').innerHTML = '📊 Opening Huntr Dashboard...';
            window.open('https://huntr.dev', '_blank');
        }
    </script>
</body>
</html>"""

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    def handle_launch(self):
        scan_id = f"HUNTR-TEST-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

        response_data = {
            "status": "launched",
            "scan_id": scan_id,
            "message": "Test assessment launched",
            "timestamp": datetime.now().isoformat()
        }

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(response_data).encode())

    def send_test_api(self):
        data = {"status": "working", "port": PORT, "time": datetime.now().isoformat()}

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def send_404(self):
        self.send_response(404)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<h1>404 - Not Found</h1>')

    def log_message(self, format, *args):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {format % args}")

def main():
    print(f"🎯 Starting Huntr Test Dashboard on port {PORT}")
    print(f"🌐 URL: http://localhost:{PORT}")

    try:
        with socketserver.TCPServer(("", PORT), SimpleHandler) as httpd:
            print(f"✅ Test server running on port {PORT}")
            httpd.serve_forever()
    except Exception as e:
        print(f"❌ Failed to start server: {e}")

if __name__ == "__main__":
    main()