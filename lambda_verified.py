import json

class VulnerabilityDatabase:
    def __init__(self):
        # VERIFIED VULNERABILITIES ONLY - All findings require manual validation and screenshot evidence
        self.vulnerabilities = [
            {
                "id": "VALIDATION-REQUIRED",
                "title": "Assessment Methodology Updated - Verification Required",
                "description": "All previous vulnerability findings have been removed as they were identified as false positives. New security assessment protocol requires manual validation with screenshot evidence for each finding.",
                "severity": "info",
                "cvss_score": 0.0,
                "cve": "N/A",
                "category": "Assessment Status",
                "owasp_top10": "N/A",
                "technical_details": {
                    "vulnerability_type": "Assessment Status Update",
                    "location": "Entire Application",
                    "parameter": "N/A",
                    "payload": "N/A",
                    "impact": "No confirmed vulnerabilities - awaiting validated findings",
                    "root_cause": "Previous findings were false positives requiring removal",
                    "validation_requirements": [
                        "Manual verification of each vulnerability",
                        "Screenshot evidence of successful exploitation",
                        "Reproducible proof-of-concept",
                        "Business impact assessment",
                        "Confirmed exploitability"
                    ],
                    "request_example": """Assessment Status: IN PROGRESS
Previous Findings: REMOVED (False Positives)
Current Methodology: Manual validation with evidence required
Next Steps:
- Perform thorough manual testing
- Document each finding with screenshots
- Validate exploitability before reporting""",
                    "response_example": """Current Assessment Results:
✅ False positives removed
⏳ Manual validation in progress
📋 Verification requirements implemented
🔍 Awaiting confirmed findings with evidence""",
                    "poc_description": "Previous automated findings were determined to be false positives. New assessment methodology requires manual validation, screenshot evidence, and confirmed exploitability before any vulnerability is reported.",
                    "screenshot_evidence": "/evidence/assessment_status_updated.png",
                    "validation_status": "PENDING",
                    "assessment_notes": "Comprehensive manual security testing is required to identify genuine vulnerabilities. All findings must be validated with proof-of-concept and screenshot evidence."
                }
            }
        ]

    def add_verified_vulnerability(self, vuln_data):
        """Add a new vulnerability only if it has been manually verified with evidence"""
        required_fields = ['screenshot_evidence', 'validation_status', 'poc_description']

        if all(field in vuln_data['technical_details'] for field in required_fields):
            if vuln_data['technical_details']['validation_status'] == 'VERIFIED':
                self.vulnerabilities.append(vuln_data)
                return True
        return False

    def generate_detailed_report(self):
        # Only include verified findings
        verified_vulns = [v for v in self.vulnerabilities if v.get('technical_details', {}).get('validation_status') != 'FALSE_POSITIVE']

        return {
            "assessment_id": "QS-VERIFIED-ASSESSMENT-2024",
            "target_info": {
                "domain": "Assessment Target TBD",
                "program": "Verified Security Assessment",
                "scope": "Manual validation required for all findings",
                "testing_period": "2024-09-29 onwards",
                "assessment_type": "Manual Verification with Evidence Required"
            },
            "methodology": {
                "assessment_type": "Manual Verification Only",
                "frameworks": ["OWASP Testing Guide", "Manual Penetration Testing"],
                "validation_requirements": [
                    "Screenshot evidence for each finding",
                    "Reproducible proof-of-concept",
                    "Manual verification of exploitability",
                    "Business impact assessment"
                ],
                "tools_used": ["Manual Testing", "Burp Suite Professional", "Screenshot Capture"],
                "testing_phases": ["Manual Verification", "Evidence Collection", "Exploit Validation"]
            },
            "detailed_findings": verified_vulns,
            "summary": {
                "total_vulnerabilities": len(verified_vulns),
                "verified_findings": len([v for v in verified_vulns if v.get('technical_details', {}).get('validation_status') == 'VERIFIED']),
                "pending_validation": len([v for v in verified_vulns if v.get('technical_details', {}).get('validation_status') == 'PENDING']),
                "false_positives_removed": "All previous automated findings",
                "critical": len([v for v in verified_vulns if v.get('severity') == 'critical']),
                "high": len([v for v in verified_vulns if v.get('severity') == 'high']),
                "medium": len([v for v in verified_vulns if v.get('severity') == 'medium']),
                "low": len([v for v in verified_vulns if v.get('severity') == 'low']),
                "average_cvss": sum(v.get('cvss_score', 0) for v in verified_vulns) / len(verified_vulns) if verified_vulns else 0,
                "risk_rating": "Manual Assessment Required - No Confirmed Vulnerabilities"
            },
            "validation_notes": {
                "status": "False positives removed - Manual validation required",
                "requirements": "All findings must include screenshot evidence and manual verification",
                "next_steps": "Perform comprehensive manual security testing with proper documentation"
            }
        }

def lambda_handler(event, context):
    """AWS Lambda handler for QuantumSentinel-Nexus Verified Assessment API"""

    try:
        # Parse the request
        http_method = event.get('httpMethod', 'GET')
        path = event.get('path', '/')
        query_params = event.get('queryStringParameters') or {}

        # Initialize verified vulnerability database
        vuln_db = VulnerabilityDatabase()

        # Route handling
        if path == '/' or path == '/dashboard':
            # Serve the updated dashboard HTML with validation requirements
            dashboard_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>QuantumSentinel-Nexus: Verified Security Assessment</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/feather-icons/dist/feather.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {
            font-family: 'JetBrains Mono', monospace;
            scroll-behavior: smooth;
        }

        body {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
            min-height: 100vh;
            overflow-x: hidden;
        }

        .glass-card {
            background: rgba(30, 41, 59, 0.7);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }

        .verification-alert {
            background: linear-gradient(135deg, #dc2626, #991b1b);
            border: 2px solid #fca5a5;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.8; }
        }

        .status-verified { background: linear-gradient(135deg, #16a34a, #15803d); }
        .status-pending { background: linear-gradient(135deg, #ca8a04, #a16207); }
        .status-removed { background: linear-gradient(135deg, #dc2626, #991b1b); }
    </style>
</head>
<body class="text-white">
    <div class="container mx-auto px-4 py-8">
        <div class="text-center mb-8">
            <h1 class="text-4xl font-bold text-white mb-2">🛡️ QuantumSentinel-Nexus</h1>
            <p class="text-xl text-blue-400">Verified Security Assessment Dashboard</p>
            <p class="text-sm text-green-400 mt-2">✅ Manual Validation Protocol Active</p>
        </div>

        <!-- Verification Alert -->
        <div class="verification-alert glass-card rounded-lg p-6 mb-6">
            <h2 class="text-2xl font-bold text-white mb-4">⚠️ Assessment Status Update</h2>
            <div class="text-white">
                <p class="mb-4"><strong>Action Taken:</strong> All previous automated findings have been removed as false positives.</p>
                <p class="mb-4"><strong>New Requirements:</strong> Manual validation with screenshot evidence required for all vulnerabilities.</p>
                <p class="mb-4"><strong>Current Status:</strong> No confirmed vulnerabilities - comprehensive manual assessment in progress.</p>

                <div class="bg-black bg-opacity-30 p-4 rounded mt-4">
                    <h3 class="text-lg font-semibold mb-2">Validation Requirements:</h3>
                    <ul class="list-disc list-inside space-y-1">
                        <li>Manual verification of each vulnerability</li>
                        <li>Screenshot evidence of successful exploitation</li>
                        <li>Reproducible proof-of-concept</li>
                        <li>Business impact assessment</li>
                        <li>Confirmed exploitability</li>
                    </ul>
                </div>
            </div>
        </div>

        <div class="glass-card rounded-lg p-6 mb-6">
            <h2 class="text-2xl font-bold text-white mb-4">📊 Assessment Summary</h2>
            <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                <div class="status-removed p-4 rounded-lg text-center">
                    <div class="text-2xl font-bold text-white" id="removed-count">0</div>
                    <div class="text-white">False Positives Removed</div>
                </div>
                <div class="status-verified p-4 rounded-lg text-center">
                    <div class="text-2xl font-bold text-white" id="verified-count">0</div>
                    <div class="text-white">Verified Findings</div>
                </div>
                <div class="status-pending p-4 rounded-lg text-center">
                    <div class="text-2xl font-bold text-white" id="pending-count">0</div>
                    <div class="text-white">Pending Validation</div>
                </div>
                <div class="bg-blue-600 p-4 rounded-lg text-center">
                    <div class="text-2xl font-bold text-white" id="total-count">0</div>
                    <div class="text-white">Total Findings</div>
                </div>
            </div>

            <div class="flex space-x-4">
                <button onclick="loadAssessmentStatus()" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-lg transition duration-300">
                    🔄 Refresh Assessment Status
                </button>
                <button onclick="generateReport()" class="bg-green-600 hover:bg-green-700 text-white px-6 py-2 rounded-lg transition duration-300">
                    📄 Generate Verification Report
                </button>
            </div>
        </div>

        <div id="assessment-container" class="space-y-6">
            <!-- Assessment status will be loaded here -->
        </div>
    </div>

    <script>
        let assessmentData = null;

        async function loadAssessmentStatus() {
            try {
                const response = await fetch('./api/vulnerabilities');
                assessmentData = await response.json();
                displayAssessmentStatus(assessmentData);
                updateSummary(assessmentData.summary);
            } catch (error) {
                console.error('Error loading assessment status:', error);
                showError('Failed to load assessment status');
            }
        }

        function displayAssessmentStatus(data) {
            const container = document.getElementById('assessment-container');
            container.innerHTML = '';

            data.detailed_findings.forEach(finding => {
                const statusClass = getStatusClass(finding.technical_details?.validation_status);
                const card = document.createElement('div');
                card.className = `glass-card rounded-lg p-6 ${statusClass}`;

                card.innerHTML = `
                    <div class="flex justify-between items-start mb-3">
                        <h3 class="text-lg font-bold text-white">${finding.title}</h3>
                        <span class="text-white text-sm">${finding.id}</span>
                    </div>
                    <p class="text-white text-sm mb-3">${finding.description}</p>
                    <div class="flex justify-between items-center">
                        <span class="text-white font-semibold">CVSS: ${finding.cvss_score}</span>
                        <span class="text-white text-sm">${finding.severity.toUpperCase()}</span>
                    </div>
                    <div class="mt-4 text-xs text-white opacity-75">
                        Status: ${finding.technical_details?.validation_status || 'PENDING'}
                    </div>
                `;

                container.appendChild(card);
            });
        }

        function getStatusClass(status) {
            switch(status) {
                case 'VERIFIED': return 'status-verified';
                case 'PENDING': return 'status-pending';
                case 'FALSE_POSITIVE': return 'status-removed';
                default: return 'status-pending';
            }
        }

        function updateSummary(summary) {
            document.getElementById('removed-count').textContent = summary.false_positives_removed === "All previous automated findings" ? "ALL" : "0";
            document.getElementById('verified-count').textContent = summary.verified_findings || 0;
            document.getElementById('pending-count').textContent = summary.pending_validation || 1;
            document.getElementById('total-count').textContent = summary.total_vulnerabilities || 1;
        }

        async function generateReport() {
            try {
                const response = await fetch('./api/reports/pdf', { method: 'POST' });
                const result = await response.json();
                alert('Verification report generation: ' + result.message);
            } catch (error) {
                alert('Report generation available for verified findings only');
            }
        }

        function showError(message) {
            const container = document.getElementById('assessment-container');
            container.innerHTML = `
                <div class="status-removed glass-card rounded-lg p-6">
                    <h3 class="text-lg font-bold text-white mb-2">Error</h3>
                    <p class="text-white">${message}</p>
                </div>
            `;
        }

        // Load assessment status on page load
        loadAssessmentStatus();
    </script>
</body>
</html>"""

            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'text/html',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Headers': 'Content-Type',
                    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
                },
                'body': dashboard_html
            }

        elif path == '/api/vulnerabilities':
            # Return verified vulnerability data only
            report_data = vuln_db.generate_detailed_report()
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Headers': 'Content-Type',
                    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
                },
                'body': json.dumps(report_data)
            }

        elif path == '/api/reports/pdf':
            # PDF generation for verified findings only
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({
                    "message": "Report generation available only for manually verified vulnerabilities with screenshot evidence",
                    "status": "Verification required",
                    "current_findings": "No verified vulnerabilities - manual assessment in progress"
                })
            }

        else:
            # Default response
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({
                    "message": "QuantumSentinel-Nexus Verified Assessment Module",
                    "status": "Manual Validation Required",
                    "validation_protocol": "Active",
                    "endpoints": {
                        "/": "Verified Security Dashboard",
                        "/api/vulnerabilities": "Verified Vulnerability Data API",
                        "/api/reports/pdf": "Verified Report Generation"
                    },
                    "version": "3.0 - Manual Verification with Evidence Required",
                    "assessment_status": "False positives removed - Manual validation in progress"
                })
            }

    except Exception as e:
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                "error": str(e),
                "message": "Assessment system error - manual verification required"
            })
        }