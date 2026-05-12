# Development Setup Guide

## Local Development with GitHub App Integration

This guide helps you set up AutoVulRepair for local development with GitHub App integration using ngrok for webhook testing.

## Prerequisites

- Python 3.8+
- PostgreSQL (local or cloud)
- Redis (local or cloud)
- ngrok account (free tier works)
- GitHub account

## 1. Environment Setup

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Install ngrok
```bash
# macOS
brew install ngrok

# Windows
choco install ngrok

# Linux
curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null
echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | sudo tee /etc/apt/sources.list.d/ngrok.list
sudo apt update && sudo apt install ngrok
```

### Setup ngrok
```bash
# Sign up at https://ngrok.com and get your auth token
ngrok config add-authtoken YOUR_NGROK_TOKEN
```

## 2. Database Setup

### Local PostgreSQL
```bash
# Create database
createdb autovulrepair_dev

# Run migrations
psql autovulrepair_dev -f migrations/add_github_app_tables.sql
```

### Or use cloud database (recommended for development)
Use Railway, Supabase, or Neon for a free PostgreSQL instance.

## 3. Environment Configuration

Create `.env` file:
```bash
# Flask Configuration
FLASK_SECRET_KEY=dev-secret-key-change-in-production
FLASK_ENV=development
FLASK_DEBUG=true

# Database (use your local or cloud database URL)
DATABASE_URL=postgresql://username:password@localhost:5432/autovulrepair_dev

# Redis (local or cloud)
REDIS_URL=redis://localhost:6379/0

# GitHub OAuth (optional for development)
GITHUB_CLIENT_ID=your-github-oauth-client-id
GITHUB_CLIENT_SECRET=your-github-oauth-client-secret

# GitHub App Integration (will be set after creating the app)
GITHUB_APP_ID=
GITHUB_APP_PRIVATE_KEY=
GITHUB_WEBHOOK_SECRET=

# Celery Configuration
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0
```

## 4. Create Development GitHub App

### Step 1: Start ngrok tunnel
```bash
# In one terminal, start your Flask app
python app.py

# In another terminal, start ngrok
ngrok http 5000
```

Note the ngrok URL (e.g., `https://abc123.ngrok.io`)

### Step 2: Create GitHub App
1. Go to GitHub Settings → Developer settings → GitHub Apps
2. Click "New GitHub App"
3. Use these settings for development:

**Basic Information:**
```
App name: autovulrepair-dev-[your-username]
Description: Development instance of AutoVulRepair
Homepage URL: https://abc123.ngrok.io
```

**Identifying and authorizing users:**
```
Callback URL: https://abc123.ngrok.io/github/installation/callback
☑️ Request user authorization (OAuth) during installation
```

**Post installation:**
```
Setup URL: https://abc123.ngrok.io/github/installation/success
☑️ Redirect on update
```

**Webhooks:**
```
☑️ Active
Webhook URL: https://abc123.ngrok.io/webhook/github
Secret: dev-webhook-secret-123
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
☑️ Only on this account (for development)
```

### Step 3: Configure Environment
1. Note the App ID from the GitHub App settings
2. Generate and download a private key
3. Update your `.env` file:

```bash
GITHUB_APP_ID=123456
GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
[paste the content of your downloaded .pem file here]
-----END RSA PRIVATE KEY-----"
GITHUB_WEBHOOK_SECRET=dev-webhook-secret-123
```

## 5. Development Workflow

### Start Development Services
```bash
# Terminal 1: Start Redis (if local)
redis-server

# Terminal 2: Start Celery worker
celery -A app.celery_app worker --loglevel=info

# Terminal 3: Start Flask app
python app.py

# Terminal 4: Start ngrok tunnel
ngrok http 5000
```

### Test the Integration
1. Visit your ngrok URL (e.g., `https://abc123.ngrok.io`)
2. Log in with GitHub
3. Install the GitHub App on a test repository
4. Push code to trigger webhook automation
5. Monitor logs for webhook processing

### Development Testing Routes
The app includes special development routes for testing:

```bash
# Test webhook payload
GET /dev/webhook-test

# Simulate webhook events
POST /dev/simulate-webhook
```

## 6. Debugging

### Enable Debug Logging
```python
# In app.py, ensure debug logging is enabled
logging.basicConfig(level=logging.DEBUG)
```

### Monitor Webhook Deliveries
1. Go to your GitHub App settings
2. Click "Advanced" tab
3. View "Recent Deliveries" to see webhook attempts

### Test Webhook Signature Verification
```bash
# Use the webhook test route to verify signatures
curl -X POST https://abc123.ngrok.io/dev/test-webhook \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: push" \
  -d '{"test": "payload"}'
```

## 7. Common Development Issues

### ngrok URL Changes
When ngrok restarts, the URL changes. Update your GitHub App settings with the new URL.

### Webhook Signature Failures
Ensure the webhook secret in your `.env` matches the one in GitHub App settings.

### Database Connection Issues
Verify your DATABASE_URL is correct and the database is running.

### Celery Worker Not Processing Jobs
Check Redis connection and ensure Celery worker is running.

## 8. Production-like Testing

### Use Stable ngrok Domain (Paid)
```bash
# With ngrok pro, you can use a stable domain
ngrok http 5000 --domain=your-domain.ngrok.io
```

### Test with Multiple Repositories
Install your development GitHub App on multiple test repositories to verify automation works correctly.

### Load Testing
Use tools like `ab` or `wrk` to test webhook handling under load:
```bash
ab -n 100 -c 10 https://abc123.ngrok.io/api/health
```

## 9. Transitioning to Production

When ready to deploy:
1. Create a production GitHub App with your production URLs
2. Update environment variables for production
3. Deploy using the deployment guide
4. Migrate any test data if needed

## 10. Development Best Practices

- Use separate GitHub Apps for development and production
- Test webhook handling with various event types
- Monitor database queries for performance
- Use feature flags for experimental features
- Keep development and production environments in sync