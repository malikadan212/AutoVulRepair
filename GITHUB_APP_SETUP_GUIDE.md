# GitHub App Setup Guide

## Step 1: Create GitHub App

Go to [GitHub Apps settings](https://github.com/settings/apps) and click "New GitHub App".

### Basic Information

**GitHub App name:** `autovulrepair-dev` (or your preferred name)
**Description:** `Automated vulnerability detection and repair for C/C++ projects`
**Homepage URL:** `http://localhost:5000` (for development)

### Identifying and authorizing users

**Callback URL:** `http://localhost:5000/github/installation/callback`

✅ **Request user authorization (OAuth) during installation:** Checked
✅ **Enable Device Flow:** Unchecked (not needed)

### Post installation

**Setup URL:** `http://localhost:5000/github/installation/success`
✅ **Redirect on update:** Checked

**Webhooks (for localhost development):**
❌ **Active:** Unchecked (disable for localhost)
**Webhook URL:** Leave empty or use placeholder
**Webhook secret:** Leave empty

> **Note:** Webhooks don't work with localhost. You can enable them later with ngrok or in production.

### Permissions

#### Repository permissions (minimal required):
- **Contents:** Read & write (to read code and create patches)
- **Pull requests:** Write (to create PRs with fixes)
- **Metadata:** Read (basic repository info)
- **Webhooks:** Read (to receive push notifications)

#### Subscribe to events:
- ✅ **Push** (to trigger scans on new commits)
- ✅ **Pull request** (to scan PRs)
- ✅ **Installation** (to manage app installations)

### Where can this GitHub App be installed?

For development: **Only on this account**
For production: **Any account**

## Step 2: Configure Environment Variables

After creating the app, update your `.env` file:

```bash
# Copy from .env.example
cp .env.example .env

# Edit .env with your GitHub App details:
GITHUB_APP_ID=123456  # Your app ID from GitHub
GITHUB_APP_NAME=autovulrepair-dev  # Your app name
GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
...your private key here...
-----END RSA PRIVATE KEY-----"
GITHUB_WEBHOOK_SECRET=your-webhook-secret-here
```

## Step 3: For Localhost Development

Since you're running via Docker, you have two options:

### Option A: Use ngrok (Recommended for real webhooks)

1. Install ngrok: `npm install -g ngrok` or download from ngrok.com
2. Start your Docker app: `docker-compose up`
3. In another terminal: `ngrok http 5000`
4. Update your GitHub App settings with the ngrok URLs:
   - **Webhook URL:** `https://your-ngrok-id.ngrok.io/webhook/github`
   - **Callback URL:** `https://your-ngrok-id.ngrok.io/github/installation/callback`

### Option B: Disable webhooks for development

Update your `.env` file:
```bash
# Disable webhooks for local development
GITHUB_WEBHOOK_SECRET=""
```

The app will still work for manual scans, but won't receive automatic push notifications.

## Step 4: Test the Integration

1. Start your Docker app: `docker-compose up`
2. Go to `http://localhost:5000`
3. Login with GitHub OAuth
4. Go to your dashboard
5. Look for "Install GitHub App" button
6. Click it to install the app on your repositories

## Step 5: Verify Installation

After installation, you should see:
- Your repositories listed in the dashboard
- Automation settings for each repository
- Ability to trigger manual scans
- (If webhooks enabled) Automatic scans on pushes

## Troubleshooting

### Common Issues:

1. **"GitHub App not configured"** - Check your environment variables
2. **Webhook signature errors** - Verify your webhook secret
3. **Permission denied** - Ensure your app has the right permissions
4. **Callback URL not working** - Make sure the URL is accessible

### Debug Endpoints:

- `http://localhost:5000/api/health` - Check if GitHub App is configured
- `http://localhost:5000/debug/session` - Check authentication state

### Logs:

Check Docker logs for detailed error messages:
```bash
docker-compose logs app
```

## Security Notes

- Keep your private key secure and never commit it to version control
- Use environment variables for all secrets
- For production, use HTTPS URLs only
- Regularly rotate your webhook secret