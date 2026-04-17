# ATOMIC Framework v10.0 - Docker Image
# Usage:
#   docker build -t atomic-framework .
#   docker run -p 5000:5000 atomic-framework --web
#   docker run atomic-framework -t https://target.com --full

FROM python:3.12-slim

LABEL maintainer="Atomic Security"
LABEL description="ATOMIC Web Vulnerability Scanner v10.0"

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
        libffi-dev \
        libssl-dev \
        gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (for layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create runtime directories
RUN mkdir -p reports shells wordlists logs

# Non-root user for security
RUN useradd -m -r atomic && chown -R atomic:atomic /app
USER atomic

# Default port for web dashboard
EXPOSE 5000

ENTRYPOINT ["python", "main.py"]
CMD ["--web", "--web-host", "0.0.0.0"]
