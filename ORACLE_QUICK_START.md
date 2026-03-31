# 🚀 Oracle Cloud Quick Start - Get AutoVulRepair Live in 15 Minutes

## Step 1: Create Your Oracle Cloud Instance (5 minutes)

### In Oracle Cloud Console:
1. **Go to**: Compute → Instances → Create Instance
2. **Configure**:
   - **Name**: `autovulrepair-server`
   - **Image**: Canonical Ubuntu 22.04
   - **Shape**: `VM.Standard.E2.1.Micro` (Always Free)
   - **Boot Volume**: 47GB (maximum for Always Free)
   - **Networking**: Use default VCN (or create new)
   - **SSH Keys**: Upload your public key or generate new pair

3. **Security List** (IMPORTANT):
   - Go to Networking → Virtual Cloud Networks → Your VCN → Security Lists
   - Add Ingress Rules:
     - **Port 22** (SSH): Source 0.0.0.0/0
     - **Port 80** (HTTP): Source 0.0.0.0/0
     - **Port 30080** (NodePort): Source 0.0.0.0/0

4. **Click "Create"** and wait for instance to be running

## Step 2: Connect to Your Instance (2 minutes)

```bash
# Get your instance's public IP from Oracle Console
# Then SSH in:
ssh ubuntu@<your-instance-public-ip>

# If using generated key pair, use:
ssh -i <path-to-private-key> ubuntu@<your-instance-public-ip>
```

## Step 3: Deploy AutoVulRepair (8 minutes)

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Git and Docker
sudo apt install -y git curl
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker ubuntu

# Log out and back in for Docker permissions
exit
# SSH back in
ssh ubuntu@<your-instance-public-ip>

# Clone your project
git clone https://github.com/your-username/autovulrepair.git
cd autovulrepair

# Make deployment script executable
chmod +x k8s/oracle-micro-deployment.sh

# Deploy AutoVulRepair
./k8s/oracle-micro-deployment.sh
```

## Step 4: Access Your Application (1 minute)

```bash
# Your app will be available at:
http://<your-instance-public-ip>:30080

# Test it:
curl http://<your-instance-public-ip>:30080/health
```

## Step 5: Update VS Code Extension

In your VS Code extension settings, update the API endpoint:
```json
{
  "autovulrepair.apiEndpoint": "http://<your-instance-public-ip>:30080"
}
```

## 🎉 You're Live!

Your AutoVulRepair is now running on Oracle Cloud for **FREE FOREVER**!

### What You Get:
- ✅ **Professional cloud deployment**
- ✅ **Public IP address** (accessible from anywhere)
- ✅ **Kubernetes orchestration** (k3s)
- ✅ **Auto-restart on failure**
- ✅ **$0/month hosting cost**

### Performance Expectations:
- **Concurrent users**: 5-10
- **Scans per hour**: 10-20
- **Response time**: 1-3 seconds
- **Uptime**: 99%+ (Oracle SLA)

### Monitoring Commands:
```bash
# Check pods
kubectl get pods -n autovulrepair

# View logs
kubectl logs -f deployment/autovulrepair-app -n autovulrepair

# Check system resources
free -h
df -h
```

## 🔄 Next Steps

### Immediate:
- ✅ Test file upload and scanning
- ✅ Verify VS Code extension connection
- ✅ Try vulnerability detection features

### Later (Optional):
- 🔄 **Upgrade to ARM A1** when available (4 vCPU, 24GB RAM)
- 🔄 **Add custom domain** (using Oracle DNS or external)
- 🔄 **Set up SSL certificate** (Let's Encrypt)
- 🔄 **Configure monitoring** (Oracle Cloud monitoring)

## 🆘 Troubleshooting

### If deployment fails:
```bash
# Check system resources
free -h
df -h

# Check k3s status
sudo systemctl status k3s

# Restart k3s if needed
sudo systemctl restart k3s
```

### If can't access from browser:
1. **Check Security List** (port 30080 open)
2. **Check instance firewall**: `sudo ufw status`
3. **Verify service**: `kubectl get svc -n autovulrepair`

### If out of memory:
```bash
# Check swap
swapon --show

# Add more swap if needed
sudo fallocate -l 1G /swapfile2
sudo chmod 600 /swapfile2
sudo mkswap /swapfile2
sudo swapon /swapfile2
```

## 💡 Pro Tips

### Cost Monitoring:
- **Always Free resources never charge**
- **Monitor usage in Oracle Console**
- **Stay within Always Free limits**

### Performance Optimization:
- **Use swap space** (essential for 1GB RAM)
- **Monitor memory usage** (`free -h`)
- **Scale down if needed** (reduce replicas)

### Security:
- **Change default passwords** in production
- **Use SSH keys only** (disable password auth)
- **Keep system updated** (`sudo apt update && sudo apt upgrade`)

## 🎯 Success Criteria

✅ **Instance created and running**
✅ **SSH access working**
✅ **k3s cluster operational**
✅ **AutoVulRepair pods running**
✅ **Web interface accessible**
✅ **Health checks passing**
✅ **VS Code extension connects**

**Total time: ~15 minutes**
**Total cost: $0/month forever**

You now have a professional-grade vulnerability scanning platform running on enterprise cloud infrastructure for absolutely free! 🚀