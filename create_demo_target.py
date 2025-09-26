#!/usr/bin/env python3
"""
QuantumSentinel-Nexus v6.0 - Demo Target Creator
Creates a safe, controlled demonstration environment for framework testing
"""

import os
import subprocess
from pathlib import Path
import docker
import time

def create_vulnerable_web_app():
    """Create a local vulnerable web application for testing"""

    demo_dir = Path("demo_environment")
    demo_dir.mkdir(exist_ok=True)

    # Create a simple vulnerable Flask app
    app_content = '''#!/usr/bin/env python3
from flask import Flask, request, render_template_string, redirect, url_for
import sqlite3
import os

app = Flask(__name__)

# Initialize database
def init_db():
    conn = sqlite3.connect('demo.db')
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'admin123')")
    conn.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('user', 'password')")
    conn.commit()
    conn.close()

@app.route('/')
def home():
    return """
    <h1>QuantumSentinel Demo Target</h1>
    <p>Safe demonstration environment for security testing</p>
    <ul>
        <li><a href="/login">Login (SQL Injection Demo)</a></li>
        <li><a href="/search">Search (XSS Demo)</a></li>
        <li><a href="/upload">Upload (File Upload Demo)</a></li>
    </ul>
    """

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Vulnerable SQL query (for demonstration)
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        conn = sqlite3.connect('demo.db')
        result = conn.execute(query).fetchone()
        conn.close()

        if result:
            return f"Welcome {result[1]}!"
        else:
            return "Invalid credentials"

    return """
    <form method="post">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    """

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Vulnerable to XSS (for demonstration)
    return f"<h1>Search Results for: {query}</h1>"

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files.get('file')
        if file:
            # Vulnerable file upload (for demonstration)
            filename = file.filename
            file.save(f"uploads/{filename}")
            return f"File {filename} uploaded successfully"

    return """
    <form method="post" enctype="multipart/form-data">
        <input type="file" name="file">
        <input type="submit" value="Upload">
    </form>
    """

if __name__ == '__main__':
    init_db()
    os.makedirs('uploads', exist_ok=True)
    app.run(host='0.0.0.0', port=5000, debug=True)
'''

    with open(demo_dir / "vulnerable_app.py", "w") as f:
        f.write(app_content)

    # Create requirements.txt
    with open(demo_dir / "requirements.txt", "w") as f:
        f.write("Flask==2.3.2\n")

    # Create Dockerfile for the demo app
    dockerfile_content = '''FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY vulnerable_app.py .
RUN mkdir uploads

EXPOSE 5000
CMD ["python", "vulnerable_app.py"]
'''

    with open(demo_dir / "Dockerfile", "w") as f:
        f.write(dockerfile_content)

    print("✅ Created vulnerable demo application")
    return demo_dir

def create_demo_network():
    """Create isolated Docker network for testing"""
    try:
        client = docker.from_env()

        # Create network if it doesn't exist
        networks = client.networks.list(names=['quantumsentinel-demo'])
        if not networks:
            network = client.networks.create(
                name='quantumsentinel-demo',
                driver='bridge'
            )
            print("✅ Created isolated demo network")
        else:
            network = networks[0]
            print("✅ Using existing demo network")

        return network
    except Exception as e:
        print(f"⚠️  Could not create Docker network: {e}")
        return None

def build_demo_target():
    """Build and start the demo target"""
    demo_dir = create_vulnerable_web_app()

    try:
        # Build the demo target
        print("🔨 Building demo target...")
        subprocess.run([
            "docker", "build", "-t", "quantumsentinel-demo-target", "."
        ], cwd=demo_dir, check=True)

        # Create network
        create_demo_network()

        # Run the demo target
        print("🚀 Starting demo target...")
        subprocess.run([
            "docker", "run", "-d",
            "--name", "demo-target",
            "--network", "quantumsentinel-demo",
            "-p", "5000:5000",
            "quantumsentinel-demo-target"
        ], check=True)

        print("✅ Demo target is running at http://localhost:5000")
        return True

    except subprocess.CalledProcessError as e:
        print(f"⚠️  Failed to build/start demo target: {e}")
        return False

def main():
    print("🎯 Creating QuantumSentinel Demo Environment")
    print("=" * 50)

    if build_demo_target():
        print("\n✅ Demo environment ready!")
        print("Target URL: http://localhost:5000")
        print("Available endpoints:")
        print("  - /login (SQL Injection)")
        print("  - /search?q=<query> (XSS)")
        print("  - /upload (File Upload)")

        print("\nYou can now run the QuantumSentinel framework against this safe target.")
    else:
        print("\n❌ Failed to create demo environment")
        print("Please ensure Docker is running and try again")

if __name__ == "__main__":
    main()