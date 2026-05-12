# 🚀 AutoVulRepair Kubernetes - Quick Start Guide

## Step 1: Install Prerequisites (Windows)

### Install Docker Desktop
1. Download from: https://www.docker.com/products/docker-desktop/
2. Install and start Docker Desktop
3. Verify: `docker --version`

### Install minikube
```powershell
# Option A: Using Chocolatey (if you have it)
choco install minikube

# Option B: Direct download
# Download from: https://minikube.sigs.k8s.io/docs/start/
# Add to PATH
```

### Install kubectl
```powershell
# Option A: Using Chocolatey
choco install kubernetes-cli

# Option B: Direct download
# Download from: https://kubernetes.io/docs/tasks/tools/install-kubectl-windows/
```

## Step 2: Start Local Kubernetes (2 minutes)

```bash
# Start minikube with enough resources
minikube start --memory=8192 --cpus=4

# Enable required addons
minikube addons enable ingress
minikube addons enable storage-provisioner

# Verify cluster is running
kubectl cluster-info
```

## Step 3: Deploy AutoVulRepair (5-10 minutes)

```bash
# Make sure you're in the project directory
cd /path/to/autovulrepair

# Run the deployment script
bash k8s/deploy-budget.sh local

# Wait for deployment to complete...
```

## Step 4: Access Your Application (2 minutes)

```bash
# Get minikube IP
minikube ip

# Add to hosts file (as Administrator):
# Windows: C:\Windows\System32\drivers\etc\hosts
# Add line: <minikube-ip> autovulrepair.local

# Visit: http://autovulrepair.local
```

## Alternative: Port Forward (Easier)

```bash
# Forward port to localhost
kubectl port-forward svc/autovulrepair-service 8080:80 -n autovulrepair

# Visit: http://localhost:8080
```

## Step 5: Test Your VS Code Extension

1. Update extension settings to point to: `http://localhost:8080` or `http://autovulrepair.local`
2. Test vulnerability scanning
3. Verify patch generation works

## Troubleshooting

### If pods are stuck pending:
```bash
kubectl get pods -n autovulrepair
kubectl describe pod <pod-name> -n autovulrepair
```

### If out of resources:
```bash
# Reduce replicas
kubectl scale deployment autovulrepair-app --replicas=1 -n autovulrepair
kubectl scale deployment celery-worker --replicas=1 -n autovulrepair
```

### Check logs:
```bash
kubectl logs -f deployment/autovulrepair-app -n autovulrepair
```

## Success Criteria

✅ All pods running: `kubectl get pods -n autovulrepair`
✅ Web interface accessible: http://localhost:8080 or http://autovulrepair.local
✅ Health checks passing: http://localhost:8080/health
✅ VS Code extension connects successfully
✅ Can upload and scan files
✅ Patch generation works

**Total time: ~15-30 minutes**
**Cost: FREE**