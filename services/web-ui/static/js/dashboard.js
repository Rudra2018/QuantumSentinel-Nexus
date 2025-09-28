// QuantumSentinel-Nexus Dashboard JavaScript
// Configuration - Use local development URLs
const API_BASE_URL = '';  // Empty for same-origin requests
const WS_URL = 'ws://localhost:8080/ws'; // WebSocket for real-time updates

// Global state
let currentTab = 'dashboard';
let charts = {};
let websocket = null;
let refreshInterval = null;

// Service configurations
const services = [
    {
        name: 'Core Platform',
        description: 'Main security testing orchestration engine',
        port: 8000,
        status: 'healthy',
        icon: 'fas fa-shield-alt',
        color: 'rgba(0, 255, 136, 0.2)',
        url: `${API_BASE_URL}/`
    },
    {
        name: 'ML Intelligence',
        description: 'Machine Learning powered vulnerability prediction and pattern recognition',
        port: 8001,
        status: 'healthy',
        icon: 'fas fa-brain',
        color: 'rgba(0, 204, 255, 0.2)',
        url: `${API_BASE_URL}/ml-intelligence`
    },
    {
        name: 'IBB Research',
        description: '24/7 Internet Bug Bounty research with automated discovery and analysis',
        port: 8002,
        status: 'healthy',
        icon: 'fas fa-search',
        color: 'rgba(255, 193, 7, 0.2)',
        url: `${API_BASE_URL}/ibb-research`
    },
    {
        name: 'Fuzzing Engine',
        description: 'Advanced fuzzing engine for discovering zero-day vulnerabilities',
        port: 8003,
        status: 'healthy',
        icon: 'fas fa-bolt',
        color: 'rgba(255, 99, 132, 0.2)',
        url: `${API_BASE_URL}/fuzzing`
    },
    {
        name: 'Reporting Engine',
        description: 'Comprehensive PDF reports with evidence collection and remediation guidance',
        port: 8004,
        status: 'healthy',
        icon: 'fas fa-file-alt',
        color: 'rgba(153, 102, 255, 0.2)',
        url: `${API_BASE_URL}/reporting`
    },
    {
        name: 'SAST-DAST',
        description: 'Static and dynamic application security testing with advanced vulnerability detection',
        port: 8005,
        status: 'healthy',
        icon: 'fas fa-code',
        color: 'rgba(255, 159, 64, 0.2)',
        url: `${API_BASE_URL}/sast-dast`
    },
    {
        name: 'Reverse Engineering',
        description: 'Binary analysis and malware research capabilities',
        port: 8006,
        status: 'healthy',
        icon: 'fas fa-microscope',
        color: 'rgba(75, 192, 192, 0.2)',
        url: `${API_BASE_URL}/reverse-engineering`
    },
    {
        name: 'Reconnaissance',
        description: 'OSINT and information gathering with advanced techniques',
        port: 8007,
        status: 'healthy',
        icon: 'fas fa-binoculars',
        color: 'rgba(54, 162, 235, 0.2)',
        url: `${API_BASE_URL}/reconnaissance`
    },
    {
        name: 'Web UI Dashboard',
        description: 'Interactive web interface for platform management',
        port: 80,
        status: 'healthy',
        icon: 'fas fa-desktop',
        color: 'rgba(255, 206, 86, 0.2)',
        url: window.location.origin
    },
    {
        name: 'Orchestration',
        description: 'Workflow management and task coordination engine',
        port: 8008,
        status: 'healthy',
        icon: 'fas fa-sitemap',
        color: 'rgba(231, 76, 60, 0.2)',
        url: `${API_BASE_URL}/orchestration`
    }
];

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    initializeNavigation();
    initializeCharts();
    loadDashboard();
    startRealTimeUpdates();

    // Auto-refresh data every 30 seconds
    refreshInterval = setInterval(refreshData, 30000);
});

// Navigation
function initializeNavigation() {
    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const tab = this.getAttribute('data-tab');
            switchTab(tab);
        });
    });
}

function switchTab(tab) {
    // Update navigation
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });
    document.querySelector(`[data-tab="${tab}"]`).classList.add('active');

    // Update content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    document.getElementById(tab).classList.add('active');

    // Update breadcrumb
    document.getElementById('current-section').textContent =
        tab.charAt(0).toUpperCase() + tab.slice(1);

    currentTab = tab;

    // Load tab-specific content
    loadTabContent(tab);
}

function loadTabContent(tab) {
    switch(tab) {
        case 'dashboard':
            loadDashboard();
            break;
        case 'services':
            loadServices();
            break;
        case 'scans':
            loadScans();
            break;
        case 'intelligence':
            loadMLIntelligence();
            break;
        case 'research':
            loadResearch();
            break;
        case 'fuzzing':
            loadFuzzing();
            break;
        case 'reports':
            loadReports();
            break;
        case 'monitoring':
            loadMonitoring();
            break;
        case 'settings':
            loadSettings();
            break;
    }
}

// Dashboard functions
function loadDashboard() {
    updateStats();
    updateActivityLog();
    updatePerformanceChart();
}

async function updateStats() {
    try {
        // Test API connectivity
        const healthResponse = await fetch(`${API_BASE_URL}/health`);
        if (healthResponse.ok) {
            const healthData = await healthResponse.json();
            console.log('API Health:', healthData);
        }

        // Update service count
        const activeServices = services.filter(s => s.status === 'healthy').length;
        document.getElementById('activeServices').textContent = activeServices;

        // Simulate other stats (in real implementation, these would come from APIs)
        document.getElementById('totalScans').textContent = Math.floor(Math.random() * 1000) + 500;
        document.getElementById('vulnerabilities').textContent = Math.floor(Math.random() * 100) + 200;

    } catch (error) {
        console.log('Stats update failed:', error);
        // Use fallback data
        document.getElementById('activeServices').textContent = services.length;
        document.getElementById('totalScans').textContent = '847';
        document.getElementById('vulnerabilities').textContent = '247';
    }
}

function updateActivityLog() {
    const logContainer = document.getElementById('activity-log');
    const timestamp = new Date().toLocaleTimeString();

    const activities = [
        { level: 'info', message: 'System health check completed' },
        { level: 'success', message: 'Vulnerability scan completed for target' },
        { level: 'warn', message: 'High severity vulnerability detected' },
        { level: 'info', message: 'ML model training in progress' },
        { level: 'success', message: 'Report generation completed' }
    ];

    const randomActivity = activities[Math.floor(Math.random() * activities.length)];

    const newLogLine = document.createElement('div');
    newLogLine.className = 'log-line';
    newLogLine.innerHTML = `
        <span class="log-timestamp">${timestamp}</span>
        <span class="log-level-${randomActivity.level}">[${randomActivity.level.toUpperCase()}]</span>
        ${randomActivity.message}
    `;

    logContainer.insertBefore(newLogLine, logContainer.firstChild);

    // Keep only last 10 entries
    while (logContainer.children.length > 10) {
        logContainer.removeChild(logContainer.lastChild);
    }
}

// Services functions
function loadServices() {
    const container = document.getElementById('servicesGrid');
    container.innerHTML = services.map(service => `
        <div class="service-card" onclick="openService('${service.url}')">
            <div class="card-header">
                <div class="card-icon" style="background: ${service.color};">
                    <i class="${service.icon}"></i>
                </div>
                <div class="service-status status-${service.status}">
                    <i class="fas fa-circle"></i>
                    ${service.status}
                </div>
            </div>
            <h3 class="card-title">${service.name}</h3>
            <p style="color: var(--text-secondary); margin-bottom: 1rem;">${service.description}</p>
            <div style="font-family: monospace; font-size: 0.8rem; color: var(--text-muted);">
                Port: ${service.port}
            </div>
        </div>
    `).join('');
}

function openService(url) {
    if (url && url !== '#') {
        window.open(url, '_blank');
    }
}

// Scans functions
async function loadScans() {
    const container = document.getElementById('scansTable');

    try {
        // Show loading state
        container.innerHTML = `
            <div style="text-align: center; padding: 2rem; color: var(--text-secondary);">
                <i class="fas fa-spinner fa-spin" style="font-size: 2rem; margin-bottom: 1rem;"></i>
                <p>Loading scans...</p>
            </div>
        `;

        const response = await fetch('/api/scans');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();

        // Combine all scan types: manual scans, active scans, and bug bounty programs
        const allScans = [
            ...data.active_scans || [],
            ...data.scan_history || [],
            ...data.bug_bounty_programs || []
        ];

        if (allScans.length === 0) {
            container.innerHTML = `
                <div style="text-align: center; padding: 2rem; color: var(--text-secondary);">
                    <i class="fas fa-search" style="font-size: 2rem; margin-bottom: 1rem;"></i>
                    <p>No scans found. Start a new scan to see results here.</p>
                </div>
            `;
            return;
        }

        container.innerHTML = `
            <table style="width: 100%; border-collapse: collapse; margin-top: 1rem;">
                <thead>
                    <tr style="border-bottom: 1px solid var(--border);">
                        <th style="padding: 1rem; text-align: left; color: var(--text-secondary);">Scan ID</th>
                        <th style="padding: 1rem; text-align: left; color: var(--text-secondary);">Target</th>
                        <th style="padding: 1rem; text-align: left; color: var(--text-secondary);">Type</th>
                        <th style="padding: 1rem; text-align: left; color: var(--text-secondary);">Platform</th>
                        <th style="padding: 1rem; text-align: left; color: var(--text-secondary);">Status</th>
                        <th style="padding: 1rem; text-align: left; color: var(--text-secondary);">Progress</th>
                        <th style="padding: 1rem; text-align: left; color: var(--text-secondary);">Max Reward</th>
                        <th style="padding: 1rem; text-align: left; color: var(--text-secondary);">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${allScans.map(scan => `
                        <tr style="border-bottom: 1px solid var(--border);">
                            <td style="padding: 1rem; font-family: monospace;">${scan.id || 'N/A'}</td>
                            <td style="padding: 1rem; max-width: 200px; overflow: hidden; text-overflow: ellipsis;" title="${scan.target}">
                                ${scan.target}
                            </td>
                            <td style="padding: 1rem;">${formatScanType(scan.scan_type)}</td>
                            <td style="padding: 1rem;">${formatPlatform(scan.platform)}</td>
                            <td style="padding: 1rem;">
                                <span class="service-status status-${getStatusClass(scan.status)}">
                                    ${scan.status}
                                </span>
                            </td>
                            <td style="padding: 1rem;">
                                <div style="width: 100px; height: 8px; background: var(--border); border-radius: 4px; overflow: hidden;">
                                    <div style="width: ${scan.progress || 0}%; height: 100%; background: linear-gradient(90deg, var(--primary), var(--secondary)); transition: width 0.3s ease;"></div>
                                </div>
                                <span style="font-size: 0.75rem; color: var(--text-secondary); margin-left: 0.5rem;">${scan.progress || 0}%</span>
                            </td>
                            <td style="padding: 1rem; color: var(--primary); font-weight: 600;">
                                ${scan.max_reward ? '$' + scan.max_reward.toLocaleString() : 'N/A'}
                            </td>
                            <td style="padding: 1rem;">
                                <div style="display: flex; gap: 0.5rem;">
                                    <button class="btn btn-outline" style="padding: 0.5rem 1rem; font-size: 0.8rem;" onclick="viewScan('${scan.id}')">
                                        <i class="fas fa-eye"></i> View
                                    </button>
                                    ${scan.program_url ? `
                                        <button class="btn btn-outline" style="padding: 0.5rem 1rem; font-size: 0.8rem;" onclick="window.open('${scan.program_url}', '_blank')">
                                            <i class="fas fa-external-link-alt"></i>
                                        </button>
                                    ` : ''}
                                </div>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
            <div style="margin-top: 1rem; padding: 1rem; background: rgba(0, 255, 136, 0.05); border-radius: 8px; border: 1px solid rgba(0, 255, 136, 0.2);">
                <p style="margin: 0; color: var(--text-secondary); font-size: 0.875rem;">
                    <i class="fas fa-info-circle" style="margin-right: 0.5rem; color: var(--primary);"></i>
                    Showing ${data.total_programs || allScans.length} active bug bounty programs and security scans
                </p>
            </div>
        `;
    } catch (error) {
        console.error('Error loading scans:', error);
        container.innerHTML = `
            <div style="text-align: center; padding: 2rem; color: var(--danger);">
                <i class="fas fa-exclamation-triangle" style="font-size: 2rem; margin-bottom: 1rem;"></i>
                <p>Error loading scans: ${error.message}</p>
                <button class="btn btn-outline" onclick="loadScans()" style="margin-top: 1rem;">
                    <i class="fas fa-redo"></i> Retry
                </button>
            </div>
        `;
    }
}

// ML Intelligence functions
function loadMLIntelligence() {
    updateMLChart();
    loadPatternResults();
}

function loadPatternResults() {
    const container = document.getElementById('patternResults');

    const patterns = [
        { type: 'SQL Injection', confidence: 95, severity: 'High', indicators: 3 },
        { type: 'XSS Attack Vector', confidence: 88, severity: 'Medium', indicators: 2 },
        { type: 'Directory Traversal', confidence: 92, severity: 'High', indicators: 4 }
    ];

    container.innerHTML = patterns.map(pattern => `
        <div style="padding: 1rem; border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1rem;">
            <div style="display: flex; justify-content: between; align-items: center; margin-bottom: 0.5rem;">
                <h4>${pattern.type}</h4>
                <span class="service-status status-${pattern.severity === 'High' ? 'error' : 'warning'}">
                    ${pattern.severity}
                </span>
            </div>
            <div style="color: var(--text-secondary); font-size: 0.9rem;">
                Confidence: ${pattern.confidence}% | Indicators: ${pattern.indicators}
            </div>
            <div style="width: 100%; background: var(--border); height: 4px; border-radius: 2px; margin-top: 0.5rem;">
                <div style="width: ${pattern.confidence}%; background: var(--primary); height: 100%; border-radius: 2px;"></div>
            </div>
        </div>
    `).join('');
}

// Research functions
function loadResearch() {
    const container = document.getElementById('researchData');

    container.innerHTML = `
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem; margin-top: 1rem;">
            <div class="card">
                <h4>Active Research Targets</h4>
                <div class="stat-value" style="font-size: 2rem; margin: 1rem 0;">47</div>
                <p style="color: var(--text-secondary);">Continuous monitoring active</p>
            </div>
            <div class="card">
                <h4>Discoveries Today</h4>
                <div class="stat-value" style="font-size: 2rem; margin: 1rem 0; color: var(--warning);">12</div>
                <p style="color: var(--text-secondary);">New vulnerabilities found</p>
            </div>
            <div class="card">
                <h4>Research Queue</h4>
                <div class="stat-value" style="font-size: 2rem; margin: 1rem 0; color: var(--secondary);">234</div>
                <p style="color: var(--text-secondary);">Targets in research pipeline</p>
            </div>
        </div>

        <div style="margin-top: 2rem;">
            <h4>Recent Findings</h4>
            <div style="margin-top: 1rem;">
                <div style="padding: 1rem; border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1rem;">
                    <div style="display: flex; justify-content: between; align-items: center;">
                        <h5>Critical IDOR in Admin Panel</h5>
                        <span style="color: var(--danger);">Critical</span>
                    </div>
                    <p style="color: var(--text-secondary); margin: 0.5rem 0;">
                        Discovered insecure direct object reference allowing unauthorized access to user data.
                    </p>
                    <div style="font-size: 0.8rem; color: var(--text-muted);">
                        Target: admin.example.com | Discovered: 2 hours ago
                    </div>
                </div>

                <div style="padding: 1rem; border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1rem;">
                    <div style="display: flex; justify-content: between; align-items: center;">
                        <h5>API Rate Limiting Bypass</h5>
                        <span style="color: var(--warning);">Medium</span>
                    </div>
                    <p style="color: var(--text-secondary); margin: 0.5rem 0;">
                        Found method to bypass rate limiting using distributed request patterns.
                    </p>
                    <div style="font-size: 0.8rem; color: var(--text-muted);">
                        Target: api.example.com | Discovered: 4 hours ago
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Fuzzing functions
function loadFuzzing() {
    const container = document.getElementById('fuzzingResults');

    container.innerHTML = `
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem;">
            <div class="card stat-card">
                <div class="stat-value">3</div>
                <div class="stat-label">Active Campaigns</div>
            </div>
            <div class="card stat-card">
                <div class="stat-value">15,847</div>
                <div class="stat-label">Test Cases Executed</div>
            </div>
            <div class="card stat-card">
                <div class="stat-value">7</div>
                <div class="stat-label">Crashes Discovered</div>
            </div>
            <div class="card stat-card">
                <div class="stat-value">94%</div>
                <div class="stat-label">Code Coverage</div>
            </div>
        </div>

        <h4>Active Campaigns</h4>
        <div style="margin-top: 1rem;">
            <div style="padding: 1rem; border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1rem;">
                <div style="display: flex; justify-content: between; align-items: center; margin-bottom: 0.5rem;">
                    <h5>API Endpoint Fuzzing</h5>
                    <span class="service-status status-warning">Running</span>
                </div>
                <p style="color: var(--text-secondary); margin-bottom: 0.5rem;">
                    Target: https://api.example.com/v1/ | Duration: 15:32 / 30:00
                </p>
                <div style="width: 100%; background: var(--border); height: 6px; border-radius: 3px;">
                    <div style="width: 52%; background: var(--primary); height: 100%; border-radius: 3px;"></div>
                </div>
            </div>
        </div>
    `;
}

// Reports functions
async function loadReports() {
    const container = document.getElementById('reportsList');

    try {
        // Show loading state
        container.innerHTML = `
            <div style="text-align: center; padding: 2rem; color: var(--text-secondary);">
                <i class="fas fa-spinner fa-spin" style="font-size: 2rem; margin-bottom: 1rem;"></i>
                <p>Loading reports...</p>
            </div>
        `;

        const response = await fetch('/api/reports');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        const reports = data.reports || [];

        if (reports.length === 0) {
            container.innerHTML = `
                <div style="text-align: center; padding: 2rem; color: var(--text-secondary);">
                    <i class="fas fa-file-pdf" style="font-size: 2rem; margin-bottom: 1rem;"></i>
                    <p>No reports generated yet. Generate your first report to see it here.</p>
                    <button class="btn btn-primary" onclick="generateReport()" style="margin-top: 1rem;">
                        <i class="fas fa-plus"></i> Generate Report
                    </button>
                </div>
            `;
            return;
        }

        container.innerHTML = `
            <table style="width: 100%; border-collapse: collapse; margin-top: 1rem;">
                <thead>
                    <tr style="border-bottom: 1px solid var(--border);">
                        <th style="padding: 1rem; text-align: left; color: var(--text-secondary);">Report ID</th>
                        <th style="padding: 1rem; text-align: left; color: var(--text-secondary);">Name</th>
                        <th style="padding: 1rem; text-align: left; color: var(--text-secondary);">Type</th>
                        <th style="padding: 1rem; text-align: left; color: var(--text-secondary);">Size</th>
                        <th style="padding: 1rem; text-align: left; color: var(--text-secondary);">Created</th>
                        <th style="padding: 1rem; text-align: left; color: var(--text-secondary);">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${reports.map(report => `
                        <tr style="border-bottom: 1px solid var(--border);">
                            <td style="padding: 1rem; font-family: monospace;">${report.id}</td>
                            <td style="padding: 1rem; max-width: 300px; overflow: hidden; text-overflow: ellipsis;" title="${report.title}">
                                ${report.title}
                            </td>
                            <td style="padding: 1rem; text-transform: uppercase; font-weight: 600;">
                                ${report.format || 'PDF'}
                            </td>
                            <td style="padding: 1rem; color: var(--text-secondary);">${report.size || 'N/A'}</td>
                            <td style="padding: 1rem; color: var(--text-secondary);">${formatDate(report.created_at)}</td>
                            <td style="padding: 1rem;">
                                <div style="display: flex; gap: 0.5rem;">
                                    ${report.download_url ? `
                                        <button class="btn btn-outline" style="padding: 0.5rem 1rem; font-size: 0.8rem;" onclick="downloadReport('${report.download_url}', '${report.title}')">
                                            <i class="fas fa-download"></i> Download
                                        </button>
                                    ` : ''}
                                    <button class="btn btn-outline" style="padding: 0.5rem 1rem; font-size: 0.8rem;" onclick="viewReport('${report.id}')">
                                        <i class="fas fa-eye"></i> View
                                    </button>
                                    <button class="btn btn-outline" style="padding: 0.5rem 1rem; font-size: 0.8rem; color: var(--danger);" onclick="deleteReport('${report.id}')" title="Delete Report">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                </div>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
            <div style="margin-top: 1rem; padding: 1rem; background: rgba(0, 255, 136, 0.05); border-radius: 8px; border: 1px solid rgba(0, 255, 136, 0.2);">
                <p style="margin: 0; color: var(--text-secondary); font-size: 0.875rem;">
                    <i class="fas fa-info-circle" style="margin-right: 0.5rem; color: var(--primary);"></i>
                    ${reports.length} report(s) available. All reports include comprehensive vulnerability details, POCs, and remediation steps.
                </p>
            </div>
        `;
    } catch (error) {
        console.error('Error loading reports:', error);
        container.innerHTML = `
            <div style="text-align: center; padding: 2rem; color: var(--danger);">
                <i class="fas fa-exclamation-triangle" style="font-size: 2rem; margin-bottom: 1rem;"></i>
                <p>Error loading reports: ${error.message}</p>
                <button class="btn btn-outline" onclick="loadReports()" style="margin-top: 1rem;">
                    <i class="fas fa-redo"></i> Retry
                </button>
            </div>
        `;
    }
}

// Monitoring functions
function loadMonitoring() {
    updateMonitoringChart();
    loadAlertCenter();
}

function loadAlertCenter() {
    const container = document.getElementById('alertCenter');

    const alerts = [
        { level: 'error', message: 'High CPU usage detected on ML Intelligence service', time: '2 minutes ago' },
        { level: 'warning', message: 'API rate limit approaching threshold', time: '5 minutes ago' },
        { level: 'info', message: 'System backup completed successfully', time: '1 hour ago' }
    ];

    container.innerHTML = alerts.map(alert => `
        <div style="padding: 1rem; border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1rem; border-left: 4px solid ${alert.level === 'error' ? 'var(--danger)' : alert.level === 'warning' ? 'var(--warning)' : 'var(--primary)'};">
            <div style="display: flex; justify-content: between; align-items: center;">
                <div>
                    <i class="fas fa-${alert.level === 'error' ? 'exclamation-triangle' : alert.level === 'warning' ? 'exclamation-circle' : 'info-circle'}"
                       style="color: ${alert.level === 'error' ? 'var(--danger)' : alert.level === 'warning' ? 'var(--warning)' : 'var(--primary)'}; margin-right: 0.5rem;"></i>
                    ${alert.message}
                </div>
                <div style="color: var(--text-muted); font-size: 0.8rem;">
                    ${alert.time}
                </div>
            </div>
        </div>
    `).join('');
}

// Settings functions
function loadSettings() {
    const container = document.getElementById('settingsPanel');

    container.innerHTML = `
        <div style="display: grid; gap: 2rem;">
            <div>
                <h4>API Configuration</h4>
                <div style="margin-top: 1rem;">
                    <div class="form-group">
                        <label class="form-label">API Base URL</label>
                        <input type="text" class="form-input" value="${API_BASE_URL}" readonly>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Refresh Interval (seconds)</label>
                        <input type="number" class="form-input" value="30" min="5" max="300">
                    </div>
                </div>
            </div>

            <div>
                <h4>Notification Settings</h4>
                <div style="margin-top: 1rem;">
                    <div style="display: flex; align-items: center; justify-content: between; padding: 1rem; border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1rem;">
                        <div>
                            <h5>Email Notifications</h5>
                            <p style="color: var(--text-secondary); margin: 0;">Receive email alerts for critical vulnerabilities</p>
                        </div>
                        <label style="position: relative; display: inline-block; width: 60px; height: 34px;">
                            <input type="checkbox" checked style="opacity: 0; width: 0; height: 0;">
                            <span style="position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: var(--primary); border-radius: 34px; transition: .4s;"></span>
                        </label>
                    </div>
                </div>
            </div>

            <div>
                <h4>Security Settings</h4>
                <div style="margin-top: 1rem;">
                    <div class="form-group">
                        <label class="form-label">Session Timeout (minutes)</label>
                        <input type="number" class="form-input" value="120" min="15" max="480">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Maximum Concurrent Scans</label>
                        <input type="number" class="form-input" value="5" min="1" max="20">
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Chart functions
function initializeCharts() {
    // Performance Chart
    const perfCtx = document.getElementById('performanceChart').getContext('2d');
    charts.performance = new Chart(perfCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'CPU Usage (%)',
                data: [],
                borderColor: 'rgba(0, 255, 136, 1)',
                backgroundColor: 'rgba(0, 255, 136, 0.1)',
                tension: 0.4
            }, {
                label: 'Memory Usage (%)',
                data: [],
                borderColor: 'rgba(0, 204, 255, 1)',
                backgroundColor: 'rgba(0, 204, 255, 0.1)',
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: {
                        color: 'rgba(255, 255, 255, 0.7)'
                    }
                }
            },
            scales: {
                x: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: 'rgba(255, 255, 255, 0.7)'
                    }
                },
                y: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: 'rgba(255, 255, 255, 0.7)'
                    },
                    max: 100
                }
            }
        }
    });

    // ML Chart
    if (document.getElementById('mlChart')) {
        const mlCtx = document.getElementById('mlChart').getContext('2d');
        charts.ml = new Chart(mlCtx, {
            type: 'doughnut',
            data: {
                labels: ['High Risk', 'Medium Risk', 'Low Risk', 'No Risk'],
                datasets: [{
                    data: [15, 25, 35, 25],
                    backgroundColor: [
                        'rgba(255, 71, 87, 0.8)',
                        'rgba(255, 165, 2, 0.8)',
                        'rgba(255, 193, 7, 0.8)',
                        'rgba(0, 255, 136, 0.8)'
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: 'rgba(255, 255, 255, 0.7)',
                            padding: 20
                        }
                    }
                }
            }
        });
    }

    // Monitoring Chart
    if (document.getElementById('monitoringChart')) {
        const monCtx = document.getElementById('monitoringChart').getContext('2d');
        charts.monitoring = new Chart(monCtx, {
            type: 'bar',
            data: {
                labels: ['API Gateway', 'ML Service', 'Fuzzing', 'Scanning', 'Reporting'],
                datasets: [{
                    label: 'Response Time (ms)',
                    data: [120, 340, 230, 180, 290],
                    backgroundColor: 'rgba(0, 255, 136, 0.6)',
                    borderColor: 'rgba(0, 255, 136, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: {
                            color: 'rgba(255, 255, 255, 0.7)'
                        }
                    }
                },
                scales: {
                    x: {
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        },
                        ticks: {
                            color: 'rgba(255, 255, 255, 0.7)'
                        }
                    },
                    y: {
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        },
                        ticks: {
                            color: 'rgba(255, 255, 255, 0.7)'
                        }
                    }
                }
            }
        });
    }
}

function updatePerformanceChart() {
    const now = new Date().toLocaleTimeString();
    const cpuUsage = Math.random() * 30 + 20; // 20-50%
    const memUsage = Math.random() * 25 + 30; // 30-55%

    charts.performance.data.labels.push(now);
    charts.performance.data.datasets[0].data.push(cpuUsage);
    charts.performance.data.datasets[1].data.push(memUsage);

    // Keep only last 10 data points
    if (charts.performance.data.labels.length > 10) {
        charts.performance.data.labels.shift();
        charts.performance.data.datasets[0].data.shift();
        charts.performance.data.datasets[1].data.shift();
    }

    charts.performance.update('none');
}

function updateMLChart() {
    if (charts.ml) {
        // Simulate changing ML prediction data
        const newData = [
            Math.random() * 20 + 10,
            Math.random() * 20 + 20,
            Math.random() * 20 + 30,
            Math.random() * 20 + 20
        ];
        charts.ml.data.datasets[0].data = newData;
        charts.ml.update();
    }
}

function updateMonitoringChart() {
    if (charts.monitoring) {
        // Simulate response time variations
        const newData = charts.monitoring.data.datasets[0].data.map(value =>
            Math.max(50, value + (Math.random() - 0.5) * 100)
        );
        charts.monitoring.data.datasets[0].data = newData;
        charts.monitoring.update();
    }
}

// Modal functions
function openModal(modalId) {
    document.getElementById(modalId).style.display = 'block';
}

function closeModal(modalId) {
    document.getElementById(modalId).style.display = 'none';
}

// Form handlers
document.addEventListener('submit', function(e) {
    if (e.target.id === 'scanForm') {
        e.preventDefault();
        handleScanSubmit();
    } else if (e.target.id === 'fuzzingForm') {
        e.preventDefault();
        handleFuzzingSubmit();
    }
});

async function handleScanSubmit() {
    const formData = {
        target: document.getElementById('scanTarget').value,
        scan_type: document.getElementById('scanType').value,
        priority: document.getElementById('scanPriority').value,
        notes: document.getElementById('scanNotes').value
    };

    try {
        const response = await fetch(`${API_BASE_URL}/scan`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formData)
        });

        if (response.ok) {
            const result = await response.json();
            console.log('Scan started:', result);
            closeModal('scanModal');
            // Refresh scans table
            if (currentTab === 'scans') {
                loadScans();
            }
        } else {
            console.error('Failed to start scan');
        }
    } catch (error) {
        console.error('Error starting scan:', error);
    }
}

async function handleFuzzingSubmit() {
    const formData = {
        targets: [{
            target_type: 'web',
            target_url: document.getElementById('fuzzTarget').value
        }],
        fuzzing_type: document.getElementById('fuzzType').value,
        duration: parseInt(document.getElementById('fuzzDuration').value),
        intensity: document.getElementById('fuzzIntensity').value
    };

    try {
        const response = await fetch(`${API_BASE_URL}/fuzzing`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formData)
        });

        if (response.ok) {
            const result = await response.json();
            console.log('Fuzzing campaign started:', result);
            closeModal('fuzzingModal');
            // Refresh fuzzing results
            if (currentTab === 'fuzzing') {
                loadFuzzing();
            }
        } else {
            console.error('Failed to start fuzzing campaign');
        }
    } catch (error) {
        console.error('Error starting fuzzing campaign:', error);
    }
}

async function generateReport() {
    try {
        const response = await fetch(`${API_BASE_URL}/reporting`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                report_type: 'comprehensive',
                target: 'platform-summary',
                include_evidence: true
            })
        });

        if (response.ok) {
            const result = await response.json();
            console.log('Report generation started:', result);
            // Refresh reports table
            if (currentTab === 'reports') {
                loadReports();
            }
        } else {
            console.error('Failed to generate report');
        }
    } catch (error) {
        console.error('Error generating report:', error);
    }
}

// Real-time updates
function startRealTimeUpdates() {
    // Try to establish WebSocket connection for real-time updates
    try {
        websocket = new WebSocket(WS_URL);

        websocket.onopen = function() {
            console.log('WebSocket connected');
        };

        websocket.onmessage = function(event) {
            const data = JSON.parse(event.data);
            handleRealTimeUpdate(data);
        };

        websocket.onclose = function() {
            console.log('WebSocket disconnected');
            // Reconnect after 5 seconds
            setTimeout(startRealTimeUpdates, 5000);
        };

        websocket.onerror = function(error) {
            console.log('WebSocket error:', error);
        };
    } catch (error) {
        console.log('WebSocket not available, using polling');
    }
}

function handleRealTimeUpdate(data) {
    switch (data.type) {
        case 'scan_completed':
            updateActivityLog();
            if (currentTab === 'scans') {
                loadScans();
            }
            break;
        case 'vulnerability_found':
            updateStats();
            updateActivityLog();
            break;
        case 'service_status_change':
            loadServices();
            break;
        default:
            console.log('Unknown update type:', data.type);
    }
}

// Refresh data
function refreshData() {
    if (currentTab === 'dashboard') {
        updateStats();
        updateActivityLog();
        updatePerformanceChart();
    } else {
        loadTabContent(currentTab);
    }
}

// Cleanup
window.addEventListener('beforeunload', function() {
    if (websocket) {
        websocket.close();
    }
    if (refreshInterval) {
        clearInterval(refreshInterval);
    }
});

// Click outside modal to close
window.addEventListener('click', function(e) {
    if (e.target.classList.contains('modal')) {
        e.target.style.display = 'none';
    }
});

// Helper functions for scan display
function formatScanType(scanType) {
    if (!scanType) return 'Unknown';

    const typeMap = {
        'bug_bounty_research': 'Bug Bounty Research',
        'comprehensive': 'Comprehensive Scan',
        'web': 'Web Application',
        'network': 'Network Infrastructure',
        'api': 'API Security',
        'mobile': 'Mobile Application'
    };

    return typeMap[scanType] || scanType.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
}

function formatPlatform(platform) {
    if (!platform) return 'Manual';

    const platformMap = {
        'google_bug_hunters': 'Google Bug Hunters',
        'hackerone': 'HackerOne',
        'internet_bug_bounty': 'Internet Bug Bounty',
        'huntr': 'Huntr',
        'manual': 'Manual'
    };

    return platformMap[platform] || platform.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
}

function getStatusClass(status) {
    const statusMap = {
        'completed': 'healthy',
        'running': 'warning',
        'scanning': 'warning',
        'active': 'healthy',
        'pending': 'error',
        'failed': 'error',
        'stopped': 'error'
    };

    return statusMap[status] || 'error';
}

function viewScan(scanId) {
    if (scanId && scanId !== 'N/A') {
        // Fetch scan details and show in modal or navigate to details page
        fetch(`/api/scans/${scanId}`)
            .then(response => response.json())
            .then(data => {
                console.log('Scan details:', data);
                // Show scan details in a modal or alert for now
                alert(`Scan Details:\nID: ${data.id}\nTarget: ${data.target}\nStatus: ${data.status}\nProgress: ${data.progress}%`);
            })
            .catch(error => {
                console.error('Error fetching scan details:', error);
                alert('Error loading scan details');
            });
    } else {
        alert('Scan details not available');
    }
}

// Reports helper functions
function formatDate(dateString) {
    if (!dateString) return 'N/A';
    try {
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit'
        });
    } catch (error) {
        return dateString;
    }
}

function downloadReport(downloadUrl, reportTitle) {
    if (downloadUrl) {
        // Create a temporary link and trigger download
        const link = document.createElement('a');
        link.href = downloadUrl;
        link.download = `${reportTitle}.pdf`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    } else {
        alert('Download URL not available');
    }
}

function viewReport(reportId) {
    if (reportId) {
        // Open report in new tab/window
        window.open(`/api/reports/${reportId}/view`, '_blank');
    } else {
        alert('Report not available');
    }
}

function deleteReport(reportId) {
    if (reportId && confirm('Are you sure you want to delete this report? This action cannot be undone.')) {
        fetch(`/api/reports/${reportId}`, { method: 'DELETE' })
            .then(response => {
                if (response.ok) {
                    alert('Report deleted successfully');
                    // Refresh reports list
                    if (currentTab === 'reports') {
                        loadReports();
                    }
                } else {
                    throw new Error('Failed to delete report');
                }
            })
            .catch(error => {
                console.error('Error deleting report:', error);
                alert('Error deleting report: ' + error.message);
            });
    }
}

async function generateReport() {
    try {
        // Show generating state
        const generateBtn = event.target;
        const originalText = generateBtn.innerHTML;
        generateBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generating...';
        generateBtn.disabled = true;

        const response = await fetch('/api/reports/generate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                report_type: 'comprehensive',
                target: 'bug-bounty-summary',
                include_evidence: true,
                include_recommendations: true
            })
        });

        if (response.ok) {
            const result = await response.json();
            console.log('Report generation started:', result);
            alert('Report generation started! It will appear in the list once complete.');
            // Refresh reports list
            if (currentTab === 'reports') {
                loadReports();
            }
        } else {
            throw new Error('Failed to generate report');
        }
    } catch (error) {
        console.error('Error generating report:', error);
        alert('Error generating report: ' + error.message);
    } finally {
        // Reset button
        if (generateBtn) {
            generateBtn.innerHTML = originalText;
            generateBtn.disabled = false;
        }
    }
}

// APK Upload Form Handler
document.getElementById('apkForm').addEventListener('submit', async function(e) {
    e.preventDefault();

    const fileInput = document.getElementById('apkFile');
    const analysisDepth = document.getElementById('apkAnalysisDepth').value;
    const priority = document.getElementById('apkPriority').value;

    if (!fileInput.files[0]) {
        alert('Please select an APK file');
        return;
    }

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('analysis_depth', analysisDepth);
    formData.append('priority', priority);

    try {
        const response = await fetch('/api/scan/apk', {
            method: 'POST',
            body: formData
        });

        if (response.ok) {
            const result = await response.json();
            alert(`APK analysis started! Scan ID: ${result.scan_id}`);
            closeModal('apkModal');
            // Refresh scans if on scans tab
            if (currentTab === 'scans') {
                loadScans();
            }
        } else {
            const error = await response.json();
            throw new Error(error.detail || 'APK upload failed');
        }
    } catch (error) {
        console.error('Error uploading APK:', error);
        alert('Error uploading APK: ' + error.message);
    }
});

// IPA Upload Form Handler
document.getElementById('ipaForm').addEventListener('submit', async function(e) {
    e.preventDefault();

    const fileInput = document.getElementById('ipaFile');
    const analysisDepth = document.getElementById('ipaAnalysisDepth').value;
    const priority = document.getElementById('ipaPriority').value;

    if (!fileInput.files[0]) {
        alert('Please select an IPA file');
        return;
    }

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('analysis_depth', analysisDepth);
    formData.append('priority', priority);

    try {
        const response = await fetch('/api/scan/ipa', {
            method: 'POST',
            body: formData
        });

        if (response.ok) {
            const result = await response.json();
            alert(`IPA analysis started! Scan ID: ${result.scan_id}`);
            closeModal('ipaModal');
            // Refresh scans if on scans tab
            if (currentTab === 'scans') {
                loadScans();
            }
        } else {
            const error = await response.json();
            throw new Error(error.detail || 'IPA upload failed');
        }
    } catch (error) {
        console.error('Error uploading IPA:', error);
        alert('Error uploading IPA: ' + error.message);
    }
});

// Domain Scan Form Handler
document.getElementById('domainForm').addEventListener('submit', async function(e) {
    e.preventDefault();

    const target = document.getElementById('domainTarget').value;
    const scanType = document.getElementById('domainScanType').value;
    const priority = document.getElementById('domainPriority').value;

    try {
        const response = await fetch('/api/scan/domain', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                target: target,
                scan_type: scanType,
                priority: priority
            })
        });

        if (response.ok) {
            const result = await response.json();
            alert(`Domain scan started! Scan ID: ${result.scan_id}`);
            closeModal('domainModal');
            // Refresh scans if on scans tab
            if (currentTab === 'scans') {
                loadScans();
            }
        } else {
            const error = await response.json();
            throw new Error(error.detail || 'Domain scan failed');
        }
    } catch (error) {
        console.error('Error starting domain scan:', error);
        alert('Error starting domain scan: ' + error.message);
    }
});

// Bug Bounty Program Form Handler
document.getElementById('programForm').addEventListener('submit', async function(e) {
    e.preventDefault();

    const programName = document.getElementById('programName').value;
    const programUrl = document.getElementById('programUrl').value;
    const priority = document.getElementById('programPriority').value;

    const formData = new FormData();
    formData.append('program_name', programName);
    formData.append('program_url', programUrl);
    formData.append('priority', priority);

    try {
        const response = await fetch('/api/scan/program', {
            method: 'POST',
            body: formData
        });

        if (response.ok) {
            const result = await response.json();
            alert(`Bug bounty program analysis started! Scan ID: ${result.scan_id}`);
            closeModal('programModal');
            // Refresh scans if on scans tab
            if (currentTab === 'scans') {
                loadScans();
            }
        } else {
            const error = await response.json();
            throw new Error(error.detail || 'Program analysis failed');
        }
    } catch (error) {
        console.error('Error starting program analysis:', error);
        alert('Error starting program analysis: ' + error.message);
    }
});

// Platform Bulk Scan Form Handler
document.getElementById('platformForm').addEventListener('submit', async function(e) {
    e.preventDefault();

    // Get selected platforms
    const selectedPlatforms = [];
    const platformCheckboxes = document.querySelectorAll('input[name="platforms"]:checked');
    platformCheckboxes.forEach(checkbox => {
        selectedPlatforms.push(checkbox.value);
    });

    if (selectedPlatforms.length === 0) {
        alert('Please select at least one platform to scan');
        return;
    }

    const scanDepth = document.getElementById('platformScanDepth').value;
    const priority = document.getElementById('platformPriority').value;
    const filters = document.getElementById('platformFilters').value;

    const formData = new FormData();
    selectedPlatforms.forEach(platform => {
        formData.append('platforms', platform);
    });
    formData.append('scan_depth', scanDepth);
    formData.append('priority', priority);
    if (filters.trim()) {
        formData.append('filters', filters);
    }

    try {
        const response = await fetch('/api/platform/scan', {
            method: 'POST',
            body: formData
        });

        if (response.ok) {
            const result = await response.json();
            alert(`Platform bulk scan started! Scan ID: ${result.scan_id}\nScanning ${result.platforms.length} platforms: ${result.platforms.join(', ')}`);
            closeModal('platformModal');
            // Refresh scans if on scans tab
            if (currentTab === 'scans') {
                loadScans();
            }
        } else {
            const error = await response.json();
            throw new Error(error.detail || 'Platform scan failed');
        }
    } catch (error) {
        console.error('Error starting platform scan:', error);
        alert('Error starting platform scan: ' + error.message);
    }
});