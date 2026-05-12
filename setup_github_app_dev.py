#!/usr/bin/env python3
"""
GitHub App Development Setup Script
Helps configure GitHub App for local development
"""

import os
import sys
import secrets
import subprocess
from pathlib import Path

def generate_webhook_secret():
    """Generate a secure webhook secret"""
    return secrets.token_urlsafe(32)

def check_docker():
    """Check if Docker is available"""
    try:
        result = subprocess.run(['docker', '--version'], capture_output=True, text=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False

def check_env_file():
    """Check if .env file exists and has GitHub App config"""
    env_path = Path('.env')
    if not env_path.exists():
        return False, "No .env file found"
    
    content = env_path.read_text()
    required_vars = ['GITHUB_APP_ID', 'GITHUB_APP_PRIVATE_KEY', 'GITHUB_WEBHOOK_SECRET']
    missing = []
    
    for var in required_vars:
        if f'{var}=' not in content or f'{var}=your-' in content or f'{var}=123456' in content:
            missing.append(var)
    
    if missing:
        return False, f"Missing or placeholder values for: {', '.join(missing)}"
    
    return True, "GitHub App configuration found"

def setup_env_file():
    """Create or update .env file with GitHub App configuration"""
    env_example = Path('.env.example')
    env_file = Path('.env')
    
    if not env_example.exists():
        print("❌ .env.example file not found")
        return False
    
    # Copy example if .env doesn't exist
    if not env_file.exists():
        env_file.write_text(env_example.read_text())
        print("✅ Created .env file from .env.example")
    
    # Generate webhook secret if needed
    content = env_file.read_text()
    if 'GITHUB_WEBHOOK_SECRET=your-webhook-secret-here' in content:
        webhook_secret = generate_webhook_secret()
        content = content.replace(
            'GITHUB_WEBHOOK_SECRET=your-webhook-secret-here',
            f'GITHUB_WEBHOOK_SECRET={webhook_secret}'
        )
        env_file.write_text(content)
        print(f"✅ Generated webhook secret: {webhook_secret}")
    
    return True

def print_setup_instructions():
    """Print setup instructions"""
    print("\n" + "="*60)
    print("🚀 GITHUB APP SETUP INSTRUCTIONS")
    print("="*60)
    
    print("\n1️⃣  CREATE GITHUB APP:")
    print("   Go to: https://github.com/settings/apps")
    print("   Click: 'New GitHub App'")
    
    print("\n2️⃣  FILL IN THE FORM:")
    print("   GitHub App name: autovulrepair-dev")
    print("   Description: Automated vulnerability detection and repair")
    print("   Homepage URL: http://localhost:5000")
    print("   Callback URL: http://localhost:5000/github/installation/callback")
    print("   Setup URL: http://localhost:5000/github/installation/success")
    print("   Webhook URL: http://localhost:5000/webhook/github")
    
    # Show webhook secret from .env
    env_file = Path('.env')
    if env_file.exists():
        content = env_file.read_text()
        for line in content.split('\n'):
            if line.startswith('GITHUB_WEBHOOK_SECRET=') and not 'your-webhook-secret-here' in line:
                secret = line.split('=', 1)[1].strip('"')
                print(f"   Webhook secret: {secret}")
                break
    
    print("\n3️⃣  PERMISSIONS (Repository):")
    print("   ✅ Contents: Read & write")
    print("   ✅ Pull requests: Write") 
    print("   ✅ Metadata: Read")
    print("   ✅ Webhooks: Read")
    
    print("\n4️⃣  SUBSCRIBE TO EVENTS:")
    print("   ✅ Push")
    print("   ✅ Pull request")
    print("   ✅ Installation")
    
    print("\n5️⃣  INSTALLATION:")
    print("   Where can this app be installed: Only on this account")
    
    print("\n6️⃣  AFTER CREATING THE APP:")
    print("   1. Copy the App ID")
    print("   2. Generate and download the private key")
    print("   3. Update your .env file with these values")
    
    print("\n7️⃣  UPDATE .ENV FILE:")
    print("   GITHUB_APP_ID=<your-app-id>")
    print("   GITHUB_APP_PRIVATE_KEY=\"-----BEGIN RSA PRIVATE KEY-----")
    print("   ...your private key content...")
    print("   -----END RSA PRIVATE KEY-----\"")
    
    print("\n8️⃣  START THE APPLICATION:")
    print("   docker-compose up")
    
    print("\n9️⃣  TEST THE INTEGRATION:")
    print("   1. Go to http://localhost:5000")
    print("   2. Login with GitHub")
    print("   3. Click 'Install GitHub App'")
    print("   4. Select repositories to scan")
    
    print("\n🔧 FOR REAL WEBHOOKS (OPTIONAL):")
    print("   1. Install ngrok: npm install -g ngrok")
    print("   2. Run: ngrok http 5000")
    print("   3. Update GitHub App webhook URL with ngrok URL")
    
    print("\n📚 DETAILED GUIDE:")
    print("   See: GITHUB_APP_SETUP_GUIDE.md")
    print("="*60)

def main():
    """Main setup function"""
    print("🔧 AutoVulRepair GitHub App Development Setup")
    print("-" * 50)
    
    # Check Docker
    if not check_docker():
        print("❌ Docker not found. Please install Docker first.")
        return 1
    
    print("✅ Docker is available")
    
    # Setup .env file
    if not setup_env_file():
        return 1
    
    # Check current configuration
    configured, message = check_env_file()
    if configured:
        print(f"✅ {message}")
        print("\n🎉 GitHub App appears to be configured!")
        print("   Run: docker-compose up")
        print("   Then go to: http://localhost:5000")
    else:
        print(f"⚠️  {message}")
        print_setup_instructions()
    
    return 0

if __name__ == '__main__':
    sys.exit(main())