#!/bin/bash
# AutoVulRepair AWS Deployment Script
# Run this on your EC2 instance

set -e

echo "=========================================="
echo "AutoVulRepair AWS Deployment"
echo "=========================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Install Docker if not installed
if ! command -v docker &> /dev/null; then
    echo "Installing Docker..."
    yum update -y
    yum install -y docker
    systemctl start docker
    systemctl enable docker
    usermod -a -G docker ec2-user
    echo "✅ Docker installed"
else
    echo "✅ Docker already installed"
fi

# Install Docker Compose if not installed
if ! command -v docker-compose &> /dev/null; then
    echo "Installing Docker Compose..."
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    echo "✅ Docker Compose installed"
else
    echo "✅ Docker Compose already installed"
fi

# Create application directory
APP_DIR="/home/ec2-user/autovulrepair"
echo "Creating application directory: $APP_DIR"
mkdir -p $APP_DIR
cd $APP_DIR

echo ""
echo "=========================================="
echo "Next Steps:"
echo "=========================================="
echo "1. Upload your application files to: $APP_DIR"
echo "2. Copy .env.production to .env"
echo "3. Run: docker-compose -f docker-compose.production.yml up -d"
echo ""
echo "Upload command from your local machine:"
echo "scp -i your-key.pem -r . ec2-user@YOUR_EC2_IP:/home/ec2-user/autovulrepair/"
echo ""
echo "=========================================="
