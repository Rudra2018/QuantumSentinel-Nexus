# Automated Screenshot Capture for Mobile Security Research

## Professional Screenshot Collection System

### iOS Screenshot Automation (Apple Security Research)
```bash
#!/bin/bash
# iOS security research screenshot automation
# For authorized Apple Security Research only

# Set up iOS screenshot capture
DEVICE_ID=$(idevice_id -l | head -1)
SCREENSHOT_DIR="evidence/screenshots"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create evidence directory structure
mkdir -p "$SCREENSHOT_DIR"

# Function to capture iOS screenshot with annotation
capture_ios_screenshot() {
    local step_name="$1"
    local description="$2"
    local filename="${TIMESTAMP}_${step_name}.png"

    echo "📸 Capturing: $description"
    idevicescreenshot -u "$DEVICE_ID" "$SCREENSHOT_DIR/$filename"

    # Add professional annotation
    convert "$SCREENSHOT_DIR/$filename" \
        -pointsize 24 -fill red -gravity SouthEast \
        -annotate +10+10 "$description" \
        "$SCREENSHOT_DIR/$filename"

    echo "✅ Saved: $filename"
}

# Example iOS security research screenshot sequence
capture_ios_screenshot "01_setup" "iOS Research Environment"
capture_ios_screenshot "02_analysis" "Security Framework Analysis"
capture_ios_screenshot "03_exploit" "Vulnerability Demonstration"
capture_ios_screenshot "04_impact" "Security Impact Evidence"
```

### Android Screenshot Automation (Google VRP)
```bash
#!/bin/bash
# Android security research screenshot automation
# For authorized Google VRP research only

SCREENSHOT_DIR="evidence/screenshots"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DEVICE_ID=$(adb devices | grep -v "List" | head -1 | cut -f1)

# Create evidence directory
mkdir -p "$SCREENSHOT_DIR"

# Function to capture Android screenshot with metadata
capture_android_screenshot() {
    local step_name="$1"
    local description="$2"
    local filename="${TIMESTAMP}_${step_name}.png"

    echo "📸 Capturing: $description"

    # Capture screenshot with ADB
    adb -s "$DEVICE_ID" exec-out screencap -p > "$SCREENSHOT_DIR/$filename"

    # Add professional timestamp and annotation
    convert "$SCREENSHOT_DIR/$filename" \
        -pointsize 20 -fill blue -gravity NorthWest \
        -annotate +10+10 "$(date '+%Y-%m-%d %H:%M:%S')" \
        -pointsize 24 -fill red -gravity SouthEast \
        -annotate +10+10 "$description" \
        "$SCREENSHOT_DIR/$filename"

    echo "✅ Saved: $filename"
}

# Example Google VRP screenshot sequence
capture_android_screenshot "01_environment" "Android Testing Setup"
capture_android_screenshot "02_chrome_analysis" "Chrome Mobile Analysis"
capture_android_screenshot "03_vulnerability" "Vulnerability Demonstration"
capture_android_screenshot "04_exploitation" "Exploitation Evidence"
capture_android_screenshot "05_impact" "Security Impact Analysis"
```

### AI/ML Testing Screenshot Automation (Huntr)
```bash
#!/bin/bash
# AI/ML mobile security testing screenshot automation
# For authorized Huntr.com research only

SCREENSHOT_DIR="evidence/screenshots"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create evidence structure
mkdir -p "$SCREENSHOT_DIR"

# Function for ML testing evidence capture
capture_ml_evidence() {
    local step_name="$1"
    local description="$2"
    local tool_output="$3"
    local filename="${TIMESTAMP}_${step_name}.png"

    echo "📸 Capturing ML Evidence: $description"

    # Capture terminal output for ML analysis
    script -q /dev/null "$tool_output" | col -b > "/tmp/ml_output.txt"

    # Create professional screenshot with terminal output
    convert -size 1920x1080 xc:black \
        -font DejaVu-Sans-Mono -pointsize 12 -fill green \
        -annotate +20+30 "@/tmp/ml_output.txt" \
        -pointsize 24 -fill yellow -gravity North \
        -annotate +0+5 "$description" \
        "$SCREENSHOT_DIR/$filename"

    echo "✅ Saved ML Evidence: $filename"
}

# Example Huntr AI/ML screenshot sequence
capture_ml_evidence "01_model_analysis" "TensorFlow Lite Model Analysis" "python analyze_model.py"
capture_ml_evidence "02_vulnerability" "Mobile ML Vulnerability Discovery" "python exploit_model.py"
capture_ml_evidence "03_ios_testing" "iOS Core ML Security Testing" "python test_coreml.py"
capture_ml_evidence "04_android_testing" "Android ML Kit Security Testing" "python test_mlkit.py"
```

## Professional Evidence Standards

### Screenshot Quality Requirements
- **Resolution:** Full device/screen resolution
- **Format:** PNG (lossless compression)
- **Timestamp:** Visible system timestamp
- **Annotation:** Clear vulnerability highlighting
- **Sequence:** Complete step-by-step process

### Video Recording for Complex Exploits
```bash
# iOS video recording (for Apple Security Research)
ffmpeg -f avfoundation -r 30 -i "Capture screen 0" \
    -vcodec libx264 -crf 18 \
    "evidence/videos/ios_exploitation_demo.mp4"

# Android screen recording (for Google VRP)
adb shell screenrecord --size 1920x1080 --bit-rate 8000000 \
    /sdcard/android_exploit_demo.mp4

# Desktop recording for AI/ML analysis (for Huntr)
ffmpeg -f x11grab -r 30 -s 1920x1080 -i :0.0 \
    -vcodec libx264 -crf 18 \
    "evidence/videos/ml_vulnerability_analysis.mp4"
```

## Evidence Organization
```
evidence/
├── screenshots/
│   ├── 20241225_140000_01_setup.png
│   ├── 20241225_140030_02_analysis.png
│   ├── 20241225_140100_03_exploit.png
│   └── 20241225_140130_04_impact.png
├── videos/
│   ├── complete_exploitation_demo.mp4
│   └── technical_analysis_walkthrough.mp4
├── tool_outputs/
│   ├── static_analysis_results.txt
│   ├── dynamic_testing_logs.txt
│   └── network_capture.pcap
└── documentation/
    ├── methodology.md
    ├── timeline.md
    └── impact_assessment.md
```
