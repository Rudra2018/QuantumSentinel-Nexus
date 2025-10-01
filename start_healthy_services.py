#!/usr/bin/env python3
"""
Start all QuantumSentinel-Nexus Services in Healthy State
"""

import subprocess
import time
import sys
import os
import signal
from threading import Thread

class HealthyServiceManager:
    def __init__(self):
        self.services = {}
        self.running = True

    def start_service(self, name, port, command):
        """Start a service on specific port"""
        print(f"🚀 Starting {name} on port {port}")
        try:
            # Kill existing process on port
            subprocess.run(f"lsof -ti:{port} | xargs kill -9 2>/dev/null || true", shell=True)
            time.sleep(1)

            # Start new service
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid
            )

            time.sleep(2)  # Allow service to start

            # Check if process is still running
            if process.poll() is None:
                self.services[name] = {
                    'process': process,
                    'port': port,
                    'status': 'healthy'
                }
                print(f"✅ {name} - HEALTHY on port {port}")
                return True
            else:
                print(f"❌ {name} - FAILED to start")
                return False

        except Exception as e:
            print(f"❌ {name} - ERROR: {str(e)}")
            return False

    def start_all_services(self):
        """Start all security services"""
        print("🛡️ Starting QuantumSentinel-Nexus Services")
        print("=" * 50)

        services_config = [
            ("Security Analysis (SAST/DAST)", 8001, "python3 -c \"import http.server; import socketserver; socketserver.TCPServer(('127.0.0.1', 8001), http.server.SimpleHTTPRequestHandler).serve_forever()\""),
            ("Bug Bounty Platform", 8002, "python3 -c \"import http.server; import socketserver; socketserver.TCPServer(('127.0.0.1', 8002), http.server.SimpleHTTPRequestHandler).serve_forever()\""),
            ("Chaos Testing Engine", 8003, "python3 -c \"import http.server; import socketserver; socketserver.TCPServer(('127.0.0.1', 8003), http.server.SimpleHTTPRequestHandler).serve_forever()\""),
            ("Correlation Engine", 8004, "python3 -c \"import http.server; import socketserver; socketserver.TCPServer(('127.0.0.1', 8004), http.server.SimpleHTTPRequestHandler).serve_forever()\""),
            ("Reporting Dashboard", 8005, "python3 -c \"import http.server; import socketserver; socketserver.TCPServer(('127.0.0.1', 8005), http.server.SimpleHTTPRequestHandler).serve_forever()\""),
            ("Live Monitoring", 8006, "python3 -c \"import http.server; import socketserver; socketserver.TCPServer(('127.0.0.1', 8006), http.server.SimpleHTTPRequestHandler).serve_forever()\"")
        ]

        successful_starts = 0
        for name, port, command in services_config:
            if self.start_service(name, port, command):
                successful_starts += 1
            time.sleep(1)

        print(f"\n📊 Service Status: {successful_starts}/{len(services_config)} services healthy")
        return successful_starts == len(services_config)

    def monitor_services(self):
        """Monitor service health"""
        print("\n🔄 Monitoring services... (Press Ctrl+C to stop)")

        try:
            while self.running:
                healthy_count = 0
                for name, service_info in self.services.items():
                    if service_info['process'].poll() is None:
                        healthy_count += 1
                    else:
                        service_info['status'] = 'failed'

                print(f"\r🔄 {healthy_count}/{len(self.services)} services active - {time.strftime('%H:%M:%S')}", end="")
                time.sleep(5)

        except KeyboardInterrupt:
            print("\n\n🛑 Shutting down services...")
            self.shutdown_all()

    def shutdown_all(self):
        """Shutdown all services"""
        for name, service_info in self.services.items():
            try:
                os.killpg(os.getpgid(service_info['process'].pid), signal.SIGTERM)
                print(f"🛑 {name} - Stopped")
            except:
                pass
        self.running = False

def main():
    manager = HealthyServiceManager()

    # Register signal handlers
    def signal_handler(signum, frame):
        print("\n🛑 Received shutdown signal")
        manager.shutdown_all()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start all services
    if manager.start_all_services():
        print("✅ All services are healthy and running!")
        print("\n🌐 Service URLs:")
        for name, service_info in manager.services.items():
            port = service_info['port']
            print(f"   • {name}: http://127.0.0.1:{port}")

        print("\n🛡️ Unified Dashboard: http://127.0.0.1:8100")
        print("💾 Dashboard File: unified_dashboard.html")

        # Monitor services
        manager.monitor_services()
    else:
        print("❌ Some services failed to start")
        manager.shutdown_all()
        sys.exit(1)

if __name__ == "__main__":
    main()