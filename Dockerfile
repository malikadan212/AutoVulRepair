# Multi-stage build for AutoVulRepair
FROM python:3.11 AS base

# Install system dependencies in stages for better reliability
# First: lightweight tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Second: clang/llvm with fuzzing support (the heavy stuff)
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libfuzzer-19-dev \
    libc++-dev \
    libc++abi-dev \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Download FuzzedDataProvider.h (not included in Debian's clang package)
RUN mkdir -p /usr/lib/llvm-19/lib/clang/19/include/fuzzer && \
    wget -q https://raw.githubusercontent.com/llvm/llvm-project/main/compiler-rt/include/fuzzer/FuzzedDataProvider.h \
    -O /usr/lib/llvm-19/lib/clang/19/include/fuzzer/FuzzedDataProvider.h

# Verify clang installation
RUN clang++ --version

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p scans logs

# Expose Flask port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

# Default command
CMD ["python", "app.py"]
