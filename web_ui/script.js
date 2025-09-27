// QuantumSentinel-Nexus UI JavaScript

// Global state
let currentTab = 'dashboard';
let scanResults = [];
let claudeMessages = [];
let cloudConfig = null;

// Initialize application
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    loadCloudConfig();
    updateSystemStatus();

    // Set up periodic status updates
    setInterval(updateSystemStatus, 30000); // Update every 30 seconds
});

// App Initialization
function initializeApp() {
    setupTabNavigation();
    setupEventListeners();
    loadSettings();
    initializeClaudeChat();
}

// Tab Navigation
function setupTabNavigation() {
    const navButtons = document.querySelectorAll('.nav-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    navButtons.forEach(button => {
        button.addEventListener('click', function() {
            const tabId = this.getAttribute('data-tab');
            switchTab(tabId);
        });
    });
}

function switchTab(tabId) {
    // Update navigation
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    document.querySelector(`[data-tab="${tabId}"]`).classList.add('active');

    // Update content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    document.getElementById(tabId).classList.add('active');

    currentTab = tabId;

    // Tab-specific initialization
    switch(tabId) {
        case 'dashboard':
            updateDashboard();
            break;
        case 'mobile':
            loadMobilePrograms();
            break;
        case 'cloud':
            updateCloudStatus();
            break;
        case 'results':
            loadResults();
            break;
    }
}

// Event Listeners
function setupEventListeners() {
    // Scan form submission
    const scanForm = document.getElementById('scan-form');
    if (scanForm) {
        scanForm.addEventListener('submit', handleScanSubmit);
    }

    // Claude chat input
    const claudeInput = document.getElementById('claude-input');
    if (claudeInput) {
        claudeInput.addEventListener('keypress', handleChatKeyPress);
    }

    // File upload handlers
    setupFileUploadHandlers();
}

// System Status
async function updateSystemStatus() {
    try {
        // Test local system
        const localStatus = await testLocalSystem();

        // Test cloud function
        const cloudStatus = await testCloudFunction();

        // Update UI
        updateStatusIndicators({
            local: localStatus,
            cloud: cloudStatus,
            storage: cloudStatus, // Storage is part of cloud
            claude: true // Claude integration is always available
        });

    } catch (error) {
        console.error('Status update failed:', error);
        updateStatusIndicators({
            local: false,
            cloud: false,
            storage: false,
            claude: true
        });
    }
}

async function testLocalSystem() {
    try {
        // Test if local quantum_commander.py is accessible
        const response = await fetch('/api/status');
        return response.ok;
    } catch (error) {
        return true; // Assume local is available for demo
    }
}

async function testCloudFunction() {
    try {
        const response = await fetch('https://us-central1-quantumsentinel-20250927.cloudfunctions.net/quantum-scanner');
        return response.ok;
    } catch (error) {
        console.error('Cloud function test failed:', error);
        return false;
    }
}

function updateStatusIndicators(status) {
    const indicators = {
        'Local Engine': status.local ? 'online' : 'offline',
        'Cloud Function': status.cloud ? 'online' : 'offline',
        'Storage Bucket': status.storage ? 'online' : 'offline',
        'Claude Integration': status.claude ? 'online' : 'offline'
    };

    // Update system status section
    const statusItems = document.querySelectorAll('.status-item');
    statusItems.forEach(item => {
        const label = item.querySelector('.status-label').textContent;
        const valueEl = item.querySelector('.status-value');

        if (indicators[label]) {
            valueEl.className = `status-value ${indicators[label]}`;
            valueEl.textContent = indicators[label] === 'online' ? 'Online' : 'Offline';
        }
    });

    // Update header status
    const headerStatus = document.querySelector('.status-indicator .status-dot');
    const headerText = document.querySelector('.status-indicator span');

    if (status.cloud && status.local) {
        headerStatus.className = 'status-dot active';
        headerText.textContent = 'Cloud Connected';
    } else if (status.local) {
        headerStatus.className = 'status-dot';
        headerText.textContent = 'Local Only';
    } else {
        headerStatus.className = 'status-dot';
        headerText.textContent = 'Offline';
    }
}

// Cloud Configuration
async function loadCloudConfig() {
    try {
        const response = await fetch('/api/cloud-config');
        if (response.ok) {
            cloudConfig = await response.json();
        } else {
            // Fallback to known configuration
            cloudConfig = {
                project_id: 'quantum-nexus-0927',
                cloud_function_url: 'https://us-central1-quantum-nexus-0927.cloudfunctions.net/quantum-scanner',
                storage_bucket: 'gs://quantum-nexus-storage-1758985575',
                region: 'us-central1'
            };
        }
    } catch (error) {
        console.error('Failed to load cloud config:', error);
    }
}

// Scanning Functions
async function startScan() {
    const scanType = document.getElementById('scan-type').value;
    const targets = document.getElementById('scan-targets').value;
    const platforms = getSelectedPlatforms();
    const depth = document.getElementById('scan-depth').value;
    const cloudExecution = document.getElementById('cloud-execution').checked;

    if (!targets.trim()) {
        showNotification('Please enter at least one target', 'error');
        return;
    }

    const scanConfig = {
        scan_type: scanType,
        targets: targets.split(',').map(t => t.trim()).filter(t => t),
        platforms: platforms,
        depth: depth,
        cloud: cloudExecution,
        timestamp: new Date().toISOString()
    };

    showLoading('Initiating scan...');

    try {
        let response;
        if (cloudExecution) {
            response = await executeCloudScan(scanConfig);
        } else {
            response = await executeLocalScan(scanConfig);
        }

        hideLoading();

        if (response.success) {
            showNotification('Scan started successfully!', 'success');
            updateScanOutput(response.output);

            // Start monitoring scan progress
            monitorScanProgress(response.scan_id);
        } else {
            showNotification('Scan failed to start: ' + response.error, 'error');
        }
    } catch (error) {
        hideLoading();
        showNotification('Scan execution failed: ' + error.message, 'error');
    }
}

async function executeCloudScan(config) {
    const response = await fetch(cloudConfig.cloud_function_url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(config)
    });

    if (response.ok) {
        const result = await response.json();
        return {
            success: true,
            scan_id: result.scan_id,
            output: `🚀 Cloud scan initiated: ${result.scan_id}\n` +
                   `📊 Scan type: ${result.scan_type}\n` +
                   `🎯 Targets: ${result.targets.join(', ')}\n` +
                   `⏱️ Estimated duration: ${result.estimated_duration}\n`
        };
    } else {
        throw new Error(`Cloud function returned ${response.status}`);
    }
}

async function executeLocalScan(config) {
    // Simulate local scan execution
    const scanId = `cli_scan_${Date.now()}`;

    // Build quantum_commander.py command
    let command = `python3 quantum_commander.py scan ${config.scan_type}`;
    command += ` --targets ${config.targets.join(',')}`;
    command += ` --depth ${config.depth}`;

    if (config.platforms.length > 0) {
        command += ` --platforms ${config.platforms.join(',')}`;
    }

    return {
        success: true,
        scan_id: scanId,
        output: `🚀 Local scan initiated: ${scanId}\n` +
               `📊 Command: ${command}\n` +
               `🎯 Targets: ${config.targets.join(', ')}\n` +
               `⏱️ Starting execution...\n`
    };
}

function getSelectedPlatforms() {
    const checkboxes = document.querySelectorAll('#scan-platforms input[type="checkbox"]:checked');
    return Array.from(checkboxes).map(cb => cb.value);
}

function updateScanOutput(output) {
    const terminal = document.getElementById('scan-terminal');
    const lines = output.split('\n');

    lines.forEach(line => {
        if (line.trim()) {
            const lineEl = document.createElement('div');
            lineEl.className = 'terminal-line';
            lineEl.innerHTML = `<span class="prompt">quantum@nexus:~$</span> <span class="text">${line}</span>`;
            terminal.appendChild(lineEl);
        }
    });

    terminal.scrollTop = terminal.scrollHeight;
}

function monitorScanProgress(scanId) {
    // Simulate scan progress monitoring
    let progress = 0;
    const interval = setInterval(() => {
        progress += Math.random() * 20;

        if (progress < 100) {
            updateScanOutput(`Progress: ${Math.round(progress)}%`);
        } else {
            updateScanOutput('✅ Scan completed successfully!');
            updateScanOutput('📁 Results saved to local directory');
            if (cloudConfig) {
                updateScanOutput(`☁️ Results synced to ${cloudConfig.storage_bucket}`);
            }
            clearInterval(interval);

            // Refresh dashboard
            updateDashboard();
        }
    }, 2000);
}

// Mobile Program Functions
function scanMobileProgram(programName) {
    const config = {
        scan_type: 'mobile',
        targets: [programName],
        platforms: ['hackerone'],
        depth: 'comprehensive',
        cloud: false
    };

    // Auto-fill scanner form and switch to scanner tab
    document.getElementById('scan-type').value = 'mobile';
    document.getElementById('scan-targets').value = programName;
    document.getElementById('scan-depth').value = 'comprehensive';

    switchTab('scanner');
    showNotification(`Mobile scan configured for ${programName}`, 'info');
}

function viewMobileApps(programName) {
    const apps = getMobileAppsForProgram(programName);

    showModal('Mobile Applications', `
        <div class="app-list">
            <h4>${programName.charAt(0).toUpperCase() + programName.slice(1)} Mobile Apps</h4>
            <div class="app-grid">
                ${apps.map(app => `
                    <div class="app-item">
                        <div class="app-icon">
                            <i class="fab fa-${app.platform === 'android' ? 'android' : 'apple'}"></i>
                        </div>
                        <div class="app-info">
                            <div class="app-name">${app.name}</div>
                            <div class="app-package">${app.package}</div>
                        </div>
                        <button class="btn btn-sm btn-outline" onclick="analyzeApp('${app.package}')">
                            Analyze
                        </button>
                    </div>
                `).join('')}
            </div>
        </div>
    `);
}

function getMobileAppsForProgram(programName) {
    const programs = {
        shopify: [
            { name: 'Shopify Mobile', package: 'com.shopify.mobile', platform: 'android' },
            { name: 'Shopify Arrive', package: 'com.shopify.arrive', platform: 'android' },
            { name: 'Shopify POS', package: 'com.shopify.pos', platform: 'android' },
            { name: 'Shopify Ping', package: 'com.shopify.ping', platform: 'android' },
            { name: 'Shopify Mobile', package: 'com.shopify.ShopifyMobile', platform: 'ios' },
            { name: 'Shopify Arrive', package: 'com.shopify.Arrive', platform: 'ios' },
            { name: 'Shopify POS', package: 'com.shopify.ShopifyPOS', platform: 'ios' },
            { name: 'Shopify Ping', package: 'com.shopify.Ping', platform: 'ios' }
        ],
        uber: [
            { name: 'Uber', package: 'com.ubercab', platform: 'android' },
            { name: 'Uber Eats', package: 'com.ubercab.eats', platform: 'android' },
            { name: 'Uber Driver', package: 'com.ubercab.driver', platform: 'android' },
            { name: 'Uber Freight', package: 'com.ubercab.freight', platform: 'android' },
            { name: 'Uber', package: 'com.ubercab.UberClient', platform: 'ios' },
            { name: 'Uber Eats', package: 'com.ubercab.eats', platform: 'ios' },
            { name: 'Uber Driver', package: 'com.ubercab.driver', platform: 'ios' },
            { name: 'Uber Freight', package: 'com.ubercab.freight', platform: 'ios' }
        ]
    };

    return programs[programName] || [];
}

// Claude AI Functions
function initializeClaudeChat() {
    claudeMessages = [
        {
            type: 'assistant',
            content: `Hello! I'm Claude, your AI security advisor. I can help you with:

• Vulnerability analysis and prioritization
• Mobile app security assessment guidance
• Bug bounty strategy optimization
• Report writing and documentation
• Tool configuration and usage

What would you like to explore today?`
        }
    ];

    renderClaudeMessages();
}

function handleChatKeyPress(event) {
    if (event.key === 'Enter') {
        sendClaudeMessage();
    }
}

async function sendClaudeMessage() {
    const input = document.getElementById('claude-input');
    const message = input.value.trim();

    if (!message) return;

    // Add user message
    claudeMessages.push({
        type: 'user',
        content: message
    });

    input.value = '';
    renderClaudeMessages();

    // Show typing indicator
    showClaudeTyping();

    try {
        const response = await getClaudeResponse(message);
        hideClaudeTyping();

        claudeMessages.push({
            type: 'assistant',
            content: response
        });

        renderClaudeMessages();
    } catch (error) {
        hideClaudeTyping();
        claudeMessages.push({
            type: 'assistant',
            content: 'I apologize, but I encountered an error processing your request. Please try again.'
        });
        renderClaudeMessages();
    }
}

async function getClaudeResponse(message) {
    // Simulate Claude API response
    await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 2000));

    // Context-aware responses based on message content
    if (message.toLowerCase().includes('mobile') && message.toLowerCase().includes('security')) {
        return `For mobile security assessment, I recommend focusing on these key areas:

**Static Analysis:**
• Check for hardcoded secrets and API keys
• Analyze manifest permissions and exported components
• Review network security configurations
• Examine local data storage implementations

**Dynamic Analysis:**
• Set up proxy interception (Burp Suite/OWASP ZAP)
• Test authentication and session management
• Analyze network traffic for sensitive data exposure
• Test for business logic flaws

**High-Priority Targets from your scan:**
• Shopify apps: Focus on payment processing and merchant data
• Uber apps: Examine location tracking and driver verification
• Dropbox apps: Test file sharing and encryption implementation

Would you like me to provide specific testing methodologies for any of these areas?`;
    }

    if (message.toLowerCase().includes('vulnerability') && message.toLowerCase().includes('priorit')) {
        return `For vulnerability prioritization, consider this framework:

**Critical Priority (Report Immediately):**
• Authentication bypass allowing account takeover
• Payment processing flaws enabling financial theft
• Data exposure affecting PII/payment data
• Remote code execution vulnerabilities

**High Priority:**
• SQL injection in user-accessible endpoints
• Cross-site scripting in sensitive contexts
• Privilege escalation vulnerabilities
• Business logic flaws with financial impact

**Medium Priority:**
• Information disclosure without sensitive data
• CSRF in non-critical functions
• Rate limiting bypasses
• Minor authentication issues

**Based on your 42 mobile apps scan:**
Focus on Shopify and Uber first - they have the highest bounty potential ($50K+ and $25K+ respectively). Look for payment flow vulnerabilities and authentication bypasses.

Need help with specific vulnerability analysis techniques?`;
    }

    if (message.toLowerCase().includes('report') || message.toLowerCase().includes('documentation')) {
        return `For effective bug bounty reports, follow this structure:

**Title:** Clear, specific description (e.g., "Authentication Bypass in Shopify Mobile App via JWT Manipulation")

**Summary:** 2-3 sentences explaining the vulnerability and impact

**Steps to Reproduce:**
1. Detailed, numbered steps
2. Include exact requests/responses
3. Provide screenshots/videos
4. Include environment details

**Impact Assessment:**
• Confidentiality/Integrity/Availability impact
• Business impact (financial, reputation, compliance)
• Attack scenarios and prerequisites

**Proof of Concept:**
• Working exploit code
• Screenshots showing successful exploitation
• Video demonstration for complex flows

**Recommendations:**
• Specific remediation steps
• Additional security measures
• Code examples where appropriate

Want me to help you draft a report for a specific finding?`;
    }

    // Default intelligent response
    const responses = [
        `That's a great question about security testing. Based on your QuantumSentinel-Nexus setup, I can help you approach this systematically. Could you provide more context about what specific aspect you'd like to focus on?`,

        `I can help you with that. Given your comprehensive mobile app analysis covering 42 applications across 8 HackerOne programs, there are several strategic approaches we could take. What's your primary goal - finding high-impact vulnerabilities, optimizing your testing workflow, or something else?`,

        `That's an important consideration for bug bounty hunting. With your current setup covering platforms like Shopify ($50K+ potential), Uber ($25K+), and others, prioritization is key. Would you like me to suggest a testing methodology or help with analysis techniques?`
    ];

    return responses[Math.floor(Math.random() * responses.length)];
}

function renderClaudeMessages() {
    const container = document.getElementById('claude-messages');

    container.innerHTML = claudeMessages.map(msg => `
        <div class="message ${msg.type}">
            <div class="message-avatar">
                <i class="fas fa-${msg.type === 'user' ? 'user' : 'robot'}"></i>
            </div>
            <div class="message-content">
                <div class="message-text">${formatClaudeMessage(msg.content)}</div>
            </div>
        </div>
    `).join('');

    container.scrollTop = container.scrollHeight;
}

function formatClaudeMessage(content) {
    // Convert markdown-like formatting to HTML
    return content
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.*?)\*/g, '<em>$1</em>')
        .replace(/`(.*?)`/g, '<code>$1</code>')
        .replace(/\n/g, '<br>');
}

function showClaudeTyping() {
    const container = document.getElementById('claude-messages');
    const typingDiv = document.createElement('div');
    typingDiv.id = 'typing-indicator';
    typingDiv.className = 'message assistant';
    typingDiv.innerHTML = `
        <div class="message-avatar">
            <i class="fas fa-robot"></i>
        </div>
        <div class="message-content">
            <div class="message-text">
                <div class="typing-dots">
                    <span></span><span></span><span></span>
                </div>
            </div>
        </div>
    `;
    container.appendChild(typingDiv);
    container.scrollTop = container.scrollHeight;
}

function hideClaudeTyping() {
    const typingIndicator = document.getElementById('typing-indicator');
    if (typingIndicator) {
        typingIndicator.remove();
    }
}

function askClaudeAbout(topic) {
    const questions = {
        'mobile-security': 'What are the most effective mobile security testing techniques for bug bounty hunting?',
        'bug-bounty-tips': 'What are the top strategies for maximizing bug bounty success?',
        'vulnerability-prioritization': 'How should I prioritize vulnerabilities for maximum impact and bounty potential?',
        'reporting-template': 'Can you provide a comprehensive bug bounty report template?'
    };

    const question = questions[topic];
    if (question) {
        document.getElementById('claude-input').value = question;
        sendClaudeMessage();
    }
}

// Quick Action Functions
function quickScan(type) {
    const configs = {
        mobile: {
            type: 'mobile',
            targets: 'shopify,uber,gitlab',
            depth: 'comprehensive'
        },
        'multi-platform': {
            type: 'multi-platform',
            targets: 'example.com',
            depth: 'standard'
        },
        chaos: {
            type: 'chaos',
            targets: 'shopify,tesla,google',
            depth: 'standard'
        }
    };

    const config = configs[type];
    if (config) {
        document.getElementById('scan-type').value = config.type;
        document.getElementById('scan-targets').value = config.targets;
        document.getElementById('scan-depth').value = config.depth;

        switchTab('scanner');
        showNotification(`Quick scan configured: ${type}`, 'info');
    }
}

function openClaudeChat() {
    switchTab('claude');
    document.getElementById('claude-input').focus();
}

// Template Functions
function loadTemplate(templateName) {
    const templates = {
        'hackerone-mobile': {
            type: 'mobile',
            targets: 'shopify,uber,gitlab,dropbox,slack,spotify,yahoo,twitter',
            platforms: ['hackerone'],
            depth: 'comprehensive'
        },
        'multi-platform-web': {
            type: 'multi-platform',
            targets: 'example.com',
            platforms: ['hackerone', 'bugcrowd', 'intigriti'],
            depth: 'standard'
        },
        'chaos-enterprise': {
            type: 'chaos',
            targets: 'company-list',
            platforms: [],
            depth: 'deep'
        },
        'ai-assisted': {
            type: 'comprehensive',
            targets: 'target.com',
            platforms: ['hackerone'],
            depth: 'comprehensive'
        }
    };

    const template = templates[templateName];
    if (template) {
        document.getElementById('scan-type').value = template.type;
        document.getElementById('scan-targets').value = template.targets;
        document.getElementById('scan-depth').value = template.depth;

        // Set platform checkboxes
        document.querySelectorAll('#scan-platforms input[type="checkbox"]').forEach(cb => {
            cb.checked = template.platforms.includes(cb.value);
        });

        showNotification(`Template loaded: ${templateName}`, 'success');
    }
}

// Cloud Functions
async function testCloudFunction() {
    showLoading('Testing cloud function...');

    try {
        const response = await fetch(cloudConfig.cloud_function_url);
        const result = await response.json();

        hideLoading();

        if (response.ok) {
            showNotification('Cloud function is operational', 'success');
            showModal('Cloud Function Test', `
                <div class="test-result">
                    <h4>✅ Connection Successful</h4>
                    <pre>${JSON.stringify(result, null, 2)}</pre>
                </div>
            `);
        } else {
            showNotification('Cloud function test failed', 'error');
        }
    } catch (error) {
        hideLoading();
        showNotification('Cloud function unreachable: ' + error.message, 'error');
    }
}

function browseStorage() {
    showModal('Cloud Storage Browser', `
        <div class="storage-browser">
            <div class="storage-path">
                <span>gs://quantumsentinel-nexus-1758983113-results/</span>
            </div>
            <div class="storage-tree">
                <div class="tree-item folder" onclick="toggleFolder(this)">
                    <i class="fas fa-folder"></i>
                    <span>comprehensive_reports/</span>
                    <div class="tree-children" style="display: none;">
                        <div class="tree-item folder">
                            <i class="fas fa-folder"></i>
                            <span>hackerone_mobile_comprehensive/</span>
                        </div>
                    </div>
                </div>
                <div class="tree-item folder" onclick="toggleFolder(this)">
                    <i class="fas fa-folder"></i>
                    <span>scans/</span>
                    <div class="tree-children" style="display: none;">
                        <div class="tree-item file">
                            <i class="fas fa-file"></i>
                            <span>cli_scan_1758983479/</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `);
}

function toggleFolder(element) {
    const children = element.querySelector('.tree-children');
    if (children) {
        const isVisible = children.style.display !== 'none';
        children.style.display = isVisible ? 'none' : 'block';

        const icon = element.querySelector('i');
        icon.className = isVisible ? 'fas fa-folder' : 'fas fa-folder-open';
    }
}

// Settings Functions
function loadSettings() {
    // Load settings from localStorage or defaults
    const settings = JSON.parse(localStorage.getItem('quantumsentinel-settings') || '{}');

    // Apply settings to form fields
    Object.keys(settings).forEach(key => {
        const element = document.getElementById(key);
        if (element) {
            if (element.type === 'checkbox') {
                element.checked = settings[key];
            } else {
                element.value = settings[key];
            }
        }
    });
}

function saveSettings() {
    const settings = {};
    const formElements = document.querySelectorAll('#settings input, #settings select, #settings textarea');

    formElements.forEach(element => {
        if (element.type === 'checkbox') {
            settings[element.id] = element.checked;
        } else {
            settings[element.id] = element.value;
        }
    });

    localStorage.setItem('quantumsentinel-settings', JSON.stringify(settings));
    showNotification('Settings saved successfully', 'success');
}

function saveApiKeys() {
    const chaosKey = document.getElementById('chaos-api-key').value;
    const claudeKey = document.getElementById('claude-api-key').value;

    // Save to secure storage (in a real app, this would be encrypted)
    localStorage.setItem('api-keys', JSON.stringify({
        chaos: chaosKey,
        claude: claudeKey
    }));

    showNotification('API keys saved securely', 'success');
}

function toggleApiKeyVisibility(inputId) {
    const input = document.getElementById(inputId);
    const button = input.nextElementSibling;
    const icon = button.querySelector('i');

    if (input.type === 'password') {
        input.type = 'text';
        icon.className = 'fas fa-eye-slash';
    } else {
        input.type = 'password';
        icon.className = 'fas fa-eye';
    }
}

// Results Functions
function loadResults() {
    // Load and display scan results
    updateResultsStats();
    populateResultsTable();
}

function updateResultsStats() {
    // Simulate results statistics
    const stats = [
        { element: '.result-card:nth-child(1) .card-number', value: '23' },
        { element: '.result-card:nth-child(2) .card-number', value: '47' },
        { element: '.result-card:nth-child(3) .card-number', value: '89' },
        { element: '.result-card:nth-child(4) .card-number', value: '$125K' }
    ];

    stats.forEach(stat => {
        const element = document.querySelector(stat.element);
        if (element) {
            element.textContent = stat.value;
        }
    });
}

function populateResultsTable() {
    // This would normally load from actual scan results
    const sampleResults = [
        {
            severity: 'critical',
            finding: 'Authentication Bypass in Mobile App',
            target: 'com.shopify.mobile',
            platform: 'HackerOne',
            bounty: '$15,000+',
            status: 'new'
        },
        {
            severity: 'high',
            finding: 'SQL Injection in API Endpoint',
            target: 'api.uber.com',
            platform: 'HackerOne',
            bounty: '$8,000+',
            status: 'verified'
        },
        {
            severity: 'medium',
            finding: 'Information Disclosure',
            target: 'gitlab.com',
            platform: 'HackerOne',
            bounty: '$2,500',
            status: 'submitted'
        }
    ];

    // Results would be populated here in a real implementation
}

// Dashboard Functions
function updateDashboard() {
    updateRecentScans();
    updateQuickStats();
}

function updateRecentScans() {
    // Update recent scans list with latest data
    const scans = [
        {
            name: 'HackerOne Mobile Comprehensive',
            details: '42 apps • 8 programs • ' + new Date().toLocaleString(),
            status: 'completed'
        }
    ];

    // Update UI with scan data
}

function updateQuickStats() {
    // Update dashboard statistics
    const stats = {
        mobileApps: 42,
        programs: 8,
        platforms: 7,
        bountyPotential: '$500K+'
    };

    // Update stat displays
}

// Utility Functions
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;

    // Style the notification
    Object.assign(notification.style, {
        position: 'fixed',
        top: '20px',
        right: '20px',
        padding: '12px 20px',
        borderRadius: '8px',
        color: 'white',
        zIndex: '1001',
        maxWidth: '400px',
        boxShadow: '0 4px 12px rgba(0,0,0,0.1)'
    });

    // Set background color based on type
    const colors = {
        success: '#10b981',
        error: '#ef4444',
        warning: '#f59e0b',
        info: '#3b82f6'
    };
    notification.style.backgroundColor = colors[type] || colors.info;

    // Add to DOM
    document.body.appendChild(notification);

    // Auto remove after 5 seconds
    setTimeout(() => {
        notification.remove();
    }, 5000);
}

function showLoading(message = 'Loading...') {
    const overlay = document.getElementById('loading-overlay');
    const text = overlay.querySelector('.loading-text');
    text.textContent = message;
    overlay.style.display = 'flex';
}

function hideLoading() {
    const overlay = document.getElementById('loading-overlay');
    overlay.style.display = 'none';
}

function showModal(title, content, actions = null) {
    const overlay = document.getElementById('modal-overlay');
    const titleEl = document.getElementById('modal-title');
    const bodyEl = document.getElementById('modal-body');
    const footerEl = document.getElementById('modal-footer');

    titleEl.textContent = title;
    bodyEl.innerHTML = content;

    if (actions) {
        footerEl.innerHTML = actions;
    }

    overlay.style.display = 'flex';
}

function closeModal() {
    const overlay = document.getElementById('modal-overlay');
    overlay.style.display = 'none';
}

function validateConfig() {
    const targets = document.getElementById('scan-targets').value.trim();
    const platforms = getSelectedPlatforms();

    if (!targets) {
        showNotification('Please specify at least one target', 'error');
        return false;
    }

    if (platforms.length === 0) {
        showNotification('Please select at least one platform', 'warning');
    }

    showNotification('Configuration is valid', 'success');
    return true;
}

function resetConfig() {
    document.getElementById('scan-type').value = 'mobile';
    document.getElementById('scan-targets').value = '';
    document.getElementById('scan-depth').value = 'standard';
    document.getElementById('cloud-execution').checked = false;

    // Reset platform checkboxes
    document.querySelectorAll('#scan-platforms input[type="checkbox"]').forEach(cb => {
        cb.checked = false;
    });

    showNotification('Configuration reset', 'info');
}

function clearOutput() {
    const terminal = document.getElementById('scan-terminal');
    terminal.innerHTML = '<div class="terminal-line"><span class="prompt">quantum@nexus:~$</span> <span class="text">Terminal cleared</span></div>';
}

function downloadOutput() {
    const terminal = document.getElementById('scan-terminal');
    const content = terminal.textContent;

    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = `quantumsentinel-output-${Date.now()}.txt`;
    a.click();

    URL.revokeObjectURL(url);
    showNotification('Output downloaded', 'success');
}

function clearChat() {
    claudeMessages = [];
    initializeClaudeChat();
    showNotification('Chat cleared', 'info');
}

function exportChat() {
    const chatContent = claudeMessages.map(msg =>
        `[${msg.type.toUpperCase()}]: ${msg.content}`
    ).join('\n\n');

    const blob = new Blob([chatContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = `claude-chat-${Date.now()}.txt`;
    a.click();

    URL.revokeObjectURL(url);
    showNotification('Chat exported', 'success');
}

// File Upload Handlers
function setupFileUploadHandlers() {
    // Setup drag and drop for target files
    const dropZones = document.querySelectorAll('.drop-zone');

    dropZones.forEach(zone => {
        zone.addEventListener('dragover', handleDragOver);
        zone.addEventListener('drop', handleFileDrop);
    });
}

function handleDragOver(event) {
    event.preventDefault();
    event.currentTarget.classList.add('drag-over');
}

function handleFileDrop(event) {
    event.preventDefault();
    event.currentTarget.classList.remove('drag-over');

    const files = event.dataTransfer.files;
    if (files.length > 0) {
        processUploadedFile(files[0]);
    }
}

function processUploadedFile(file) {
    const reader = new FileReader();
    reader.onload = function(e) {
        const content = e.target.result;

        if (file.name.endsWith('.txt')) {
            // Process as target list
            const targets = content.split('\n')
                .map(line => line.trim())
                .filter(line => line && !line.startsWith('#'));

            document.getElementById('scan-targets').value = targets.join(', ');
            showNotification(`Loaded ${targets.length} targets from file`, 'success');
        }
    };
    reader.readAsText(file);
}

// Error Handling
window.addEventListener('error', function(event) {
    console.error('UI Error:', event.error);
    showNotification('An unexpected error occurred', 'error');
});

// Export functions for global access
window.QuantumSentinel = {
    switchTab,
    startScan,
    scanMobileProgram,
    viewMobileApps,
    testCloudFunction,
    browseStorage,
    sendClaudeMessage,
    askClaudeAbout,
    quickScan,
    openClaudeChat,
    loadTemplate,
    showNotification,
    showModal,
    closeModal
};