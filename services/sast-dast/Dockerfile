# Multi-stage build for SAST/DAST service
FROM python:3.11-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim

# Install runtime dependencies and security tools
RUN apt-get update && apt-get install -y \
    curl \
    jq \
    wget \
    git \
    # Network scanning tools
    nmap \
    masscan \
    netcat-openbsd \
    # Web application security tools
    nikto \
    dirb \
    gobuster \
    # Additional security tools
    openssl \
    binutils \
    file \
    # Browser dependencies for Selenium
    chromium \
    firefox-esr \
    # Mobile testing dependencies
    default-jdk \
    android-tools-adb \
    android-tools-fastboot \
    # Python and Node.js for additional tools
    nodejs \
    npm \
    python3-pip \
    # System tools
    unzip \
    zip \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei vulnerability scanner
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip \
    && unzip nuclei_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_linux_amd64.zip

# Install ffuf web fuzzer
RUN wget -q https://github.com/ffuf/ffuf/releases/latest/download/ffuf_linux_amd64.tar.gz \
    && tar -xzf ffuf_linux_amd64.tar.gz \
    && mv ffuf /usr/local/bin/ \
    && rm ffuf_linux_amd64.tar.gz

# Install Frida for mobile dynamic analysis
RUN pip3 install frida-tools

# Install Android SDK (minimal)
ENV ANDROID_HOME=/opt/android-sdk
ENV PATH=$PATH:$ANDROID_HOME/tools:$ANDROID_HOME/platform-tools
RUN mkdir -p $ANDROID_HOME && \
    wget -q https://dl.google.com/android/repository/commandlinetools-linux-9477386_latest.zip && \
    unzip commandlinetools-linux-9477386_latest.zip -d $ANDROID_HOME && \
    rm commandlinetools-linux-9477386_latest.zip

# Create user and set permissions
RUN groupadd -r quantum && useradd -r -g quantum quantum \
    && chown -R quantum:quantum $ANDROID_HOME

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy application code
COPY . /app/

# Set permissions
RUN chown -R quantum:quantum /app
USER quantum

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

# Expose port
EXPOSE 8001

# Start application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001", "--workers", "2"]