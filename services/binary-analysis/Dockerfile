FROM python:3.11-slim

# Install system dependencies for binary analysis
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    binutils \
    file \
    gdb \
    bsdextrautils \
    strace \
    ltrace \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r quantum && useradd -r -g quantum quantum

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements-simple.txt requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY main.py /app/main.py

# Copy the simplified binary analysis agent
COPY simple_binary_agent.py /app/ai_agents/binary_analysis_agent.py

# Create necessary directories
RUN mkdir -p /app/ai_agents /app/uploads /app/temp /app/logs && \
    touch /app/ai_agents/__init__.py

# Create service IPs file
RUN echo "# Service Discovery Configuration" > /app/service_ips.txt && \
    echo "quantumsentinel-orchestration: orchestration-service" >> /app/service_ips.txt && \
    echo "quantumsentinel-ml-intelligence: ml-service" >> /app/service_ips.txt && \
    echo "quantumsentinel-reconnaissance: reconnaissance-service" >> /app/service_ips.txt

# Set permissions
RUN chown -R quantum:quantum /app && \
    chmod +x /app/main.py

USER quantum

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8008/health || exit 1

# Expose port
EXPOSE 8008

# Start application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8008"]