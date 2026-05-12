# AWS Budget-Optimized Deployment Guide �

**BUDGET-CONSCIOUS SETUP**: Deploy AutoVulRepair on AWS with $100 credits for demos and testing with on-demand start/stop capability.

## � Budget Strategy Overview

**Total Budget**: $100 AWS Credits  
**Usage Pattern**: On-demand for demos/testing only  
**Estimated Runtime**: 40-50 hours of active usage  
**Cost per Hour**: ~$2-2.50 when running  

## 🏗️ Optimized Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                   BUDGET-OPTIMIZED AWS SETUP                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    EC2 INSTANCE                         │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │    │
│  │  │    Flask    │  │ PostgreSQL  │  │    Redis    │    │    │
│  │  │     App     │  │  (Docker)   │  │  (Docker)   │    │    │
│  │  └─────────────┘  └─────────────┘  └─────────────┘    │    │
│  │                                                         │    │
│  │  All services run on single t3.medium instance        │    │
│  │  Start/Stop as needed for demos                        │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                 │
│  ┌─────────────┐    ┌──────────────┐    ┌─────────────────┐    │
│  │ Elastic IP  │    │      S3      │    │   CloudWatch    │    │
│  │ (Optional)  │    │ File Storage │    │   Basic Logs    │    │
│  └─────────────┘    └──────────────┘    └─────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## � Cost Breakdown (Per Hour When Running)

- **EC2 t3.medium**: $0.0416/hour (~$1.00/day if running 24h)
- **EBS Storage (50GB)**: $0.10/month (~$0.003/hour)
- **S3 Storage**: $0.023/GB/month (minimal for demos)
- **Data Transfer**: ~$0.09/GB (minimal for testing)
- **Elastic IP**: $0.005/hour when running

**Total: ~$2.00-2.50/hour when active**  
**Monthly if always on: ~$60-75** (but we'll only run for demos!)

## 📋 Prerequisites

- AWS Account with $100 credits
- AWS CLI installed and configured
- Docker installed locally
- SSH key pair for EC2 access

## 🚀 Quick Setup Plan (Budget-Optimized)

### Phase 1: One-Time Setup (5 minutes)
1. **Create EC2 Instance**
   - Instance Type: `t3.medium` (2 vCPU, 4GB RAM)
   - AMI: Amazon Linux 2023
   - Storage: 50GB GP3 EBS
   - Security Group: HTTP (80), HTTPS (443), SSH (22), Custom (5000)

2. **Create S3 Bucket**
   - Bucket for scan artifacts
   - Enable versioning
   - Lifecycle policy to delete after 30 days

3. **Setup Docker Environment**
   - Install Docker and Docker Compose on EC2
   - Upload your project files
   - Configure environment variables

### Phase 2: Application Deployment (10 minutes)
1. **Deploy Application Stack**
   ```bash
   # On EC2 instance
   docker-compose -f docker-compose-v2.yml up -d
   ```

2. **Configure Database**
   - PostgreSQL runs in Docker container
   - Data persisted on EBS volume
   - Automatic backups via EBS snapshots

3. **Setup Monitoring**
   - Basic CloudWatch monitoring
   - Custom metrics for application health
   - Alerts for high resource usage

### Phase 3: Access & Security (5 minutes)
1. **Configure Access**
   - Elastic IP (optional, $3.65/month if unused)
   - Security groups for proper access
   - SSH key for secure access

2. **SSL Certificate**
   - Use Let's Encrypt (free)
   - Or AWS Certificate Manager if using domain

## 🎮 Start/Stop Operations

### Starting the System (2 minutes)
```bash
# Start EC2 instance
aws ec2 start-instances --instance-ids i-1234567890abcdef0

# Wait for instance to be running
aws ec2 wait instance-running --instance-ids i-1234567890abcdef0

# SSH into instance and start services
ssh -i your-key.pem ec2-user@your-instance-ip
cd /home/ec2-user/autovulrepair
docker-compose -f docker-compose-v2.yml up -d

# Check status
docker-compose -f docker-compose-v2.yml ps
```

### Stopping the System (1 minute)
```bash
# SSH into instance and stop services
ssh -i your-key.pem ec2-user@your-instance-ip
cd /home/ec2-user/autovulrepair
docker-compose -f docker-compose-v2.yml down

# Stop EC2 instance to save costs
aws ec2 stop-instances --instance-ids i-1234567890abcdef0
```

### Automated Start/Stop Scripts
```bash
# start-demo.sh
#!/bin/bash
echo "🚀 Starting AutoVulRepair demo environment..."
aws ec2 start-instances --instance-ids $INSTANCE_ID
aws ec2 wait instance-running --instance-ids $INSTANCE_ID
INSTANCE_IP=$(aws ec2 describe-instances --instance-ids $INSTANCE_ID --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
echo "✅ Instance started at: http://$INSTANCE_IP:5000"

# stop-demo.sh  
#!/bin/bash
echo "🛑 Stopping AutoVulRepair demo environment..."
ssh -i $KEY_PATH ec2-user@$INSTANCE_IP "cd autovulrepair && docker-compose down"
aws ec2 stop-instances --instance-ids $INSTANCE_ID
echo "✅ Instance stopped. Costs minimized."
```

## 💡 Budget Optimization Strategies

### 1. **Instance Scheduling**
- Use AWS Instance Scheduler (free)
- Automatically start/stop based on schedule
- Run only during business hours for demos

### 2. **Storage Optimization**
- Use GP3 instead of GP2 (20% cheaper)
- Enable EBS optimization
- Regular cleanup of old scan data

### 3. **Data Transfer Minimization**
- Use CloudFront for static assets (free tier)
- Compress responses
- Minimize external API calls

### 4. **Monitoring & Alerts**
- Set up billing alerts at $50, $75, $90
- Monitor resource usage
- Auto-stop if costs exceed threshold

## 📊 Usage Tracking

### Cost Monitoring Dashboard
```bash
# Get current month costs
aws ce get-cost-and-usage \
    --time-period Start=2024-01-01,End=2024-01-31 \
    --granularity MONTHLY \
    --metrics BlendedCost

# Set up billing alert
aws cloudwatch put-metric-alarm \
    --alarm-name "BudgetAlert" \
    --alarm-description "Alert when costs exceed $75" \
    --metric-name EstimatedCharges \
    --namespace AWS/Billing \
    --statistic Maximum \
    --period 86400 \
    --threshold 75 \
    --comparison-operator GreaterThanThreshold
```

### Usage Log Template
```
Demo Session Log:
- Date: ___________
- Start Time: ___________
- End Time: ___________
- Duration: _____ hours
- Estimated Cost: $_____ 
- Purpose: ___________
- Notes: ___________

Running Total:
- Sessions: _____
- Total Hours: _____
- Total Cost: $_____
- Remaining Budget: $_____
```

## 🎯 Demo Scenarios & Time Estimates

### Quick Demo (30 minutes) - $1.25
- Start instance (2 min)
- Show web interface (10 min)
- Run sample scan (15 min)
- Stop instance (3 min)

### Full Feature Demo (2 hours) - $5.00
- Complete vulnerability scanning
- Fuzzing demonstration
- AI repair showcase
- VS Code extension demo

### Development Session (4 hours) - $10.00
- Code changes and testing
- Database operations
- Performance testing
- Feature development

## 🔧 One-Time Setup Commands

### EC2 Instance Setup
```bash
# Launch instance
aws ec2 run-instances \
    --image-id ami-0abcdef1234567890 \
    --count 1 \
    --instance-type t3.medium \
    --key-name your-key-pair \
    --security-group-ids sg-xxxxxxxxx \
    --subnet-id subnet-xxxxxxxxx \
    --block-device-mappings '[{
        "DeviceName": "/dev/xvda",
        "Ebs": {
            "VolumeSize": 50,
            "VolumeType": "gp3",
            "DeleteOnTermination": true
        }
    }]' \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=AutoVulRepair-Demo}]'
```

### Initial Instance Configuration
```bash
# SSH into instance
ssh -i your-key.pem ec2-user@your-instance-ip

# Install Docker
sudo yum update -y
sudo yum install -y docker
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -a -G docker ec2-user

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Upload project files (from local machine)
scp -i your-key.pem -r . ec2-user@your-instance-ip:/home/ec2-user/autovulrepair/
```

## 🎪 Demo Preparation Checklist

### Before Each Demo
- [ ] Check AWS billing dashboard
- [ ] Ensure sufficient credits remaining
- [ ] Start instance using script
- [ ] Verify all services are running
- [ ] Test key functionality
- [ ] Prepare demo scenarios

### After Each Demo
- [ ] Stop all services
- [ ] Stop EC2 instance
- [ ] Update usage log
- [ ] Check costs incurred
- [ ] Plan next demo timing

## 🚨 Emergency Procedures

### If Costs Spike Unexpectedly
1. **Immediate Actions**
   ```bash
   # Stop all instances
   aws ec2 stop-instances --instance-ids $(aws ec2 describe-instances --query 'Reservations[].Instances[].InstanceId' --output text)
   
   # Check what's running
   aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,State.Name,InstanceType]' --output table
   ```

2. **Cost Analysis**
   ```bash
   # Get detailed cost breakdown
   aws ce get-cost-and-usage \
       --time-period Start=$(date -d '7 days ago' +%Y-%m-%d),End=$(date +%Y-%m-%d) \
       --granularity DAILY \
       --metrics BlendedCost \
       --group-by Type=DIMENSION,Key=SERVICE
   ```

### If Instance Won't Start
1. Check instance limits
2. Verify security groups
3. Check EBS volume status
4. Review CloudWatch logs

## 📈 Scaling for Success

### If Demo Goes Well (Future Expansion)
1. **Upgrade to Production Setup**
   - Move to RDS for database
   - Add Load Balancer
   - Implement auto-scaling

2. **Cost Optimization**
   - Reserved instances for predictable usage
   - Spot instances for development
   - S3 Intelligent Tiering

3. **Enhanced Features**
   - CI/CD pipeline
   - Multi-region deployment
   - Advanced monitoring

## 🎯 Success Metrics

### Technical Metrics
- Application uptime during demos
- Response time < 2 seconds
- Zero failed deployments
- All features working correctly

### Budget Metrics
- Stay under $100 total spend
- Cost per demo session
- Efficient resource utilization
- No surprise charges

---

**This budget-optimized approach gives you maximum demo value from your $100 AWS credits while maintaining professional presentation quality and full feature access.**