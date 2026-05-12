# AutoVulRepair Deployment Guide

## Overview
This guide covers deploying AutoVulRepair with GitHub App integration on Railway (recommended) or other platforms.

## Prerequisites
- GitHub account
- Railway account (or alternative platform)
- PostgreSQL database
- Redis instance (for background jobs)

## 1. GitHub App Setup

### Create GitHub App
1. Go to GitHub Settings → Developer settings → GitHub Apps
2. Click "New GitHub App"
3. Fill in the configuration:

**Basic Information:**
```
App name: autovulrepair-[your-username]
Description: Automated vulnerability detection and repair for C/C++ projects
Homepage URL: https://your-app.railway.app (update after deployment)
```

**Identifying and authorizing users:**
```
Callback URL: https://your-app.railway.app/github/installation/callback
☑️ Request user authorization (OAuth) during installation
☑️ Expire user authorization tokens
☑️ Enable Device Flow
```

**Post installation:**
```
Setup URL: https://your-app.railway.app/github/installation/success
☑️ Redirect on update
```

**Webhooks:**
```
☑️ Active
Webhook URL: https://your-app.railway.app/webhook/github
Secret: [generate random 32-character string]
```

**Repository permissions:**
```
☑️ Contents: Read & write
☑️ Issues: Write
☑️ Pull requests: Write
☑️ Metadata: Read
☑️ Commit statuses: Write
```

**Subscribe to events:**
```
☑️ Installation
☑️ Push
☑️ Pull request
```

**Where can this GitHub App be installed:**
```
☑️ Any account
```

### Download Private Key
1. After creating the app, scroll down to "Private keys"
2. Click "Generate a private key"
3. Download the `.pem` file - you'll need this for deployment

### Note App Details
Save these values for environment configuration:
- App ID (shown at top of app settings)
- Private key file content
- Webhook secret you generated

## 2. Railway Deployment

### Step 1: Prepare Repository
1. Ensure your code is pushed to GitHub
2. Make sure `railway.toml`, `Procfile`, and `nixpacks.toml` are in your repo

### Step 2: Create Railway Project
1. Go to [Railway](https://railway.app)
2. Click "New Project"
3. Select "Deploy from GitHub repo"
4. Choose your AutoVulRepair repository

### Step 3: Add Database Services
1. In your Railway project, click "New Service"
2. Add PostgreSQL:
   - Click "Database" → "PostgreSQL"
   - Note the connection details
3. Add Redis:
   - Click "Database" → "Redis"
   - Note the connection details

### Step 4: Configure Environment Variables
In Railway project settings → Variables, add:

```bash
# Flask Configuration
FLASK_SECRET_KEY=your-random-secret-key-here
FLASK_ENV=production

# Database
DATABASE_URL=postgresql://username:password@host:port/database
REDIS_URL=redis://username:password@host:port

# GitHub OAuth (optional - for user login)
GITHUB_CLIENT_ID=your-github-oauth-client-id
GITHUB_CLIENT_SECRET=your-github-oauth-client-secret

# GitHub App Integration
GITHUB_APP_ID=123456
GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
[paste your private key content here]
-----END RSA PRIVATE KEY-----"
GITHUB_WEBHOOK_SECRET=your-webhook-secret-here

# Celery Configuration
CELERY_BROKER_URL=redis://username:password@host:port
CELERY_RESULT_BACKEND=redis://username:password@host:port

# Optional: External Services
OPENAI_API_KEY=your-openai-key-for-ai-patches
```

### Step 5: Deploy
1. Railway will automatically deploy when you push to your main branch
2. Monitor the deployment logs
3. Once deployed, note your app URL (e.g., `https://autovulrepair-production.railway.app`)

### Step 6: Update GitHub App URLs
1. Go back to your GitHub App settings
2. Update the URLs with your Railway deployment URL:
   - Homepage URL: `https://your-app.railway.app`
   - Callback URL: `https://your-app.railway.app/github/installation/callback`
   - Setup URL: `https://your-app.railway.app/github/installation/success`
   - Webhook URL: `https://your-app.railway.app/webhook/github`

## 3. Database Migration

After deployment, run the database migration:

```bash
# Connect to your Railway PostgreSQL and run:
psql $DATABASE_URL -f migrations/add_github_app_tables.sql
```

Or use Railway's built-in database console.

## 4. Testing the Integration

### Test Basic Functionality
1. Visit your deployed app URL
2. Try the health check: `https://your-app.railway.app/api/health`
3. Should return JSON with status "ok"

### Test GitHub App Installation
1. Go to `https://your-app.railway.app`
2. Log in with GitHub OAuth
3. Click "Install GitHub App" 
4. Select repositories to enable automation
5. Verify installation success page

### Test Webhook Automation
1. Push code to a repository with the app installed
2. Check your app logs for webhook processing
3. Verify scans are triggered automatically

## 5. Alternative Deployment Platforms

### Heroku
```bash
# Install Heroku CLI and login
heroku create your-app-name
heroku addons:create heroku-postgresql:mini
heroku addons:create heroku-redis:mini

# Set environment variables
heroku config:set FLASK_SECRET_KEY=your-secret
heroku config:set GITHUB_APP_ID=123456
# ... (set all other variables)

# Deploy
git push heroku main
```

### Render
1. Connect your GitHub repository
2. Set build command: `pip install -r requirements.txt`
3. Set start command: `python app.py`
4. Add PostgreSQL and Redis services
5. Configure environment variables

### DigitalOcean App Platform
1. Create new app from GitHub
2. Configure build settings
3. Add database components
4. Set environment variables
5. Deploy

## 6. Production Considerations

### Security
- Use strong secrets for all keys
- Enable HTTPS (Railway provides this automatically)
- Regularly rotate GitHub App private keys
- Monitor webhook signatures

### Monitoring
- Set up logging aggregation
- Monitor database performance
- Track webhook delivery success rates
- Set up alerts for failed scans

### Scaling
- Configure Celery workers for background processing
- Use Redis for caching and job queues
- Consider database connection pooling
- Monitor resource usage

## 7. Troubleshooting

### Common Issues

**GitHub App webhook not receiving events:**
- Verify webhook URL is correct and accessible
- Check webhook secret matches environment variable
- Ensure app has correct permissions

**Database connection errors:**
- Verify DATABASE_URL format
- Check database service is running
- Ensure migration has been run

**Celery workers not processing jobs:**
- Verify Redis connection
- Check CELERY_BROKER_URL configuration
- Ensure worker processes are running

### Debug Mode
For development, set:
```bash
FLASK_ENV=development
FLASK_DEBUG=true
```

### Logs
Check application logs for detailed error information:
```bash
# Railway
railway logs

# Heroku  
heroku logs --tail

# Local development
python app.py
```

## 8. Next Steps

After successful deployment:
1. Install the GitHub App on your repositories
2. Configure automation settings per repository
3. Monitor scan results and performance
4. Set up notifications and integrations
5. Customize vulnerability detection rules

## Support

For issues:
1. Check the troubleshooting section
2. Review application logs
3. Verify environment configuration
4. Test with a simple repository first