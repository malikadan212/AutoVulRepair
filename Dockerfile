# Multi-stage build for AutoVulRepair Production
FROM python:3.11-slim AS base

# Install system dependencies in stages for better reliability
# First: lightweight tools and security updates
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Second: clang/llvm with fuzzing support (the heavy stuff)
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libfuzzer-19-dev \
    libc++-dev \
    libc++abi-dev \
    libc++1-19 \
    libclang-rt-19-dev \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Download FuzzedDataProvider.h (not included in Debian's clang package)
RUN mkdir -p /usr/lib/llvm-19/lib/clang/19/include/fuzzer && \
    wget -q https://raw.githubusercontent.com/llvm/llvm-project/main/compiler-rt/include/fuzzer/FuzzedDataProvider.h \
    -O /usr/lib/llvm-19/lib/clang/19/include/fuzzer/FuzzedDataProvider.h

# Verify clang installation
RUN clang++ --version

# Create non-root user for security
RUN groupadd -r autovulrepair && useradd -r -g autovulrepair autovulrepair

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements-no-rag.txt requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Make scripts executable
RUN chmod +x celery_worker.py celery_beat.py celery_flower.py docker-entrypoint.sh

# Create necessary directories with proper permissions
RUN mkdir -p scans logs faiss_indexes && \
    chown -R autovulrepair:autovulrepair /app

# Keep as root for Docker socket access
# USER autovulrepair

# Expose Flask port
EXPOSE 5000

# Add health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Default command
ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["python", "app.py"]
