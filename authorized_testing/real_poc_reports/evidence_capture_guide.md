# Professional Screenshot and Evidence Capture Guide

## Screenshot Standards for Professional PoC

### Technical Requirements
- **Format:** PNG (lossless compression)
- **Resolution:** Full device resolution (no cropping unless necessary)
- **Timestamp:** System timestamp visible when relevant
- **Quality:** High quality, clear text and UI elements
- **File Naming:** Descriptive naming convention (step1_vulnerability_trigger.png)

### Content Guidelines
- **Clear Focus:** Highlight the vulnerability or security issue
- **Context:** Include enough surrounding UI for context
- **Sensitive Data:** Blur or redact personal/sensitive information
- **Annotations:** Use callouts or arrows to highlight key elements
- **Sequence:** Capture complete step-by-step process

### Screenshot Categories

#### 1. Environment Setup Screenshots
- Testing device information
- Tool configuration screens
- Proxy setup confirmation
- Application installation verification

#### 2. Static Analysis Screenshots
- MobSF analysis results
- Binary analysis output
- Security feature detection
- Code pattern analysis

#### 3. Dynamic Testing Screenshots
- Frida console output
- Burp Suite traffic interception
- Runtime manipulation results
- Authentication bypass demonstrations

#### 4. Vulnerability Evidence Screenshots
- Before/after exploitation comparison
- Sensitive data exposure
- Unauthorized access demonstrations
- System compromise evidence

#### 5. Impact Demonstration Screenshots
- User account compromise
- Data theft demonstration
- Privilege escalation evidence
- Financial impact simulation (authorized environments only)

## Video Recording Standards

### Technical Specifications
- **Format:** MP4 with H.264 encoding
- **Resolution:** 1080p minimum (4K preferred for mobile screens)
- **Frame Rate:** 30fps minimum
- **Audio:** Clear narration explaining each step
- **Duration:** 2-5 minutes per vulnerability

### Content Structure
1. **Introduction (30 seconds)**
   - Vulnerability overview
   - Authorization statement
   - Testing environment overview

2. **Setup Demonstration (1 minute)**
   - Tool configuration
   - Target application preparation
   - Initial state verification

3. **Exploitation Process (2-3 minutes)**
   - Step-by-step vulnerability exploitation
   - Real-time commentary
   - Technical details explanation

4. **Impact Demonstration (30 seconds)**
   - Clear demonstration of impact
   - Data exposure or unauthorized access
   - Business impact explanation

5. **Conclusion (30 seconds)**
   - Summary of findings
   - Remediation recommendations
   - Responsible disclosure statement

## Evidence Organization Structure

```
evidence/
├── screenshots/
│   ├── 01_authorization/
│   │   ├── bug_bounty_acceptance.png
│   │   └── scope_confirmation.png
│   ├── 02_setup/
│   │   ├── testing_environment.png
│   │   ├── tool_configuration.png
│   │   └── target_app_info.png
│   ├── 03_static_analysis/
│   │   ├── mobsf_results.png
│   │   ├── binary_analysis.png
│   │   └── security_controls.png
│   ├── 04_dynamic_testing/
│   │   ├── frida_instrumentation.png
│   │   ├── network_interception.png
│   │   └── runtime_manipulation.png
│   └── 05_vulnerability_evidence/
│       ├── authentication_bypass.png
│       ├── data_exposure.png
│       └── unauthorized_access.png
├── videos/
│   ├── complete_exploitation_demo.mp4
│   ├── impact_demonstration.mp4
│   └── remediation_verification.mp4
├── network_logs/
│   ├── burp_project_complete.burp
│   ├── traffic_analysis.xml
│   └── api_calls_log.txt
└── tool_outputs/
    ├── frida_scripts/
    ├── mobsf_report.pdf
    └── complete_testing_log.txt
```

## Professional Editing Guidelines

### Screenshot Editing
- Use professional annotation tools (Snagit, Markup, Annotate)
- Consistent color scheme for annotations (red for vulnerabilities, blue for information)
- Clear, readable callouts and arrows
- Professional font for text annotations
- Consistent sizing and positioning

### Video Editing
- Professional editing software (Camtasia, Adobe Premiere, Final Cut Pro)
- Clean transitions between scenes
- Consistent audio levels
- Professional title cards and annotations
- Clear, concise narration script

## Legal and Ethical Considerations

### Content Restrictions
- No personally identifiable information (PII)
- No financial account details
- No proprietary/confidential business information
- No screenshots that could harm other users

### Authorization Documentation
- Always include proof of authorization
- Reference specific bug bounty program terms
- Document testing boundaries and limitations
- Include responsible disclosure timeline

### Professional Standards
- Maintain ethical testing boundaries
- Focus on security improvement, not sensationalism
- Provide constructive remediation guidance
- Follow coordinated disclosure practices
