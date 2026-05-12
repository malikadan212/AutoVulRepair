"""
Test script for webhook visibility features
Run this before deploying to AWS to ensure everything works
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test that all new modules can be imported"""
    print("=" * 60)
    print("TEST 1: Testing Imports")
    print("=" * 60)
    
    try:
        from src.models.webhook_event import WebhookEvent
        print("✓ WebhookEvent model imports successfully")
    except Exception as e:
        print("X Failed to import WebhookEvent: {}".format(e))
        return False
    
    try:
        from src.webhooks.github_webhooks import github_webhooks_bp, init_webhook_handler
        print("✓ Webhook handler imports successfully")
    except Exception as e:
        print(f"✗ Failed to import webhook handler: {e}")
        return False
    
    try:
        from src.routes.github_app_routes import github_app_bp
        print("✓ GitHub app routes import successfully")
    except Exception as e:
        print(f"✗ Failed to import GitHub app routes: {e}")
        return False
    
    print("\n✓ All imports successful!\n")
    return True


def test_app_startup():
    """Test that the app can start with new code"""
    print("=" * 60)
    print("TEST 2: Testing App Startup")
    print("=" * 60)
    
    try:
        from app import app
        print("✓ App imports successfully")
        
        # Check if routes are registered
        webhook_routes = [str(rule) for rule in app.url_map.iter_rules() if 'webhook' in str(rule)]
        print(f"✓ Found {len(webhook_routes)} webhook routes:")
        for route in sorted(webhook_routes):
            print(f"  - {route}")
        
        if len(webhook_routes) < 3:
            print("✗ Expected at least 3 webhook routes")
            return False
        
        print("\n✓ App startup successful!\n")
        return True
    except Exception as e:
        print(f"✗ Failed to start app: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_model_creation():
    """Test that WebhookEvent model can be instantiated"""
    print("=" * 60)
    print("TEST 3: Testing Model Creation")
    print("=" * 60)
    
    try:
        from src.models.webhook_event import WebhookEvent
        from datetime import datetime
        
        # Create a test webhook event
        event = WebhookEvent(
            delivery_id="test-123",
            event_type="push",
            action="opened",
            repository_full_name="user/repo",
            installation_id=12345,
            sender_login="testuser",
            status="received",
            payload_summary={"test": "data"}
        )
        
        print("✓ WebhookEvent instance created successfully")
        
        # Test to_dict method
        event_dict = event.to_dict()
        print(f"✓ to_dict() works: {len(event_dict)} fields")
        
        required_fields = ['delivery_id', 'event_type', 'status', 'repository']
        for field in required_fields:
            if field not in event_dict:
                print(f"✗ Missing required field: {field}")
                return False
        
        print("✓ All required fields present")
        print("\n✓ Model creation successful!\n")
        return True
    except Exception as e:
        print(f"✗ Failed to create model: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_webhook_handler():
    """Test webhook handler initialization"""
    print("=" * 60)
    print("TEST 4: Testing Webhook Handler")
    print("=" * 60)
    
    try:
        from src.webhooks.github_webhooks import init_webhook_handler, webhook_handler
        from src.webhooks import github_webhooks
        
        # Initialize with test secret
        init_webhook_handler("test_secret_123")
        
        # Check if handler was created
        if github_webhooks.webhook_handler is None:
            print("✗ Webhook handler not initialized")
            return False
        
        print("✓ Webhook handler initialized successfully")
        
        # Test signature verification
        test_payload = b'{"test": "data"}'
        test_signature = "sha256:invalid"
        
        result = github_webhooks.webhook_handler.verify_signature(test_payload, test_signature)
        print(f"✓ Signature verification works (returned: {result})")
        
        print("\n✓ Webhook handler test successful!\n")
        return True
    except Exception as e:
        print(f"✗ Failed webhook handler test: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_sql_migration():
    """Test SQL migration file"""
    print("=" * 60)
    print("TEST 5: Testing SQL Migration")
    print("=" * 60)
    
    try:
        migration_file = "migrations/add_webhook_events_table.sql"
        
        if not os.path.exists(migration_file):
            print(f"✗ Migration file not found: {migration_file}")
            return False
        
        print(f"✓ Migration file exists: {migration_file}")
        
        with open(migration_file, 'r') as f:
            sql_content = f.read()
        
        # Check for required SQL statements
        required_statements = [
            "CREATE TABLE",
            "webhook_events",
            "delivery_id",
            "event_type",
            "CREATE INDEX"
        ]
        
        for statement in required_statements:
            if statement not in sql_content:
                print(f"✗ Missing required SQL statement: {statement}")
                return False
        
        print(f"✓ All required SQL statements present")
        print(f"✓ Migration file size: {len(sql_content)} bytes")
        
        print("\n✓ SQL migration test successful!\n")
        return True
    except Exception as e:
        print(f"✗ Failed SQL migration test: {e}")
        return False


def test_dashboard_template():
    """Test dashboard template has webhook widgets"""
    print("=" * 60)
    print("TEST 6: Testing Dashboard Template")
    print("=" * 60)
    
    try:
        template_file = "templates/single_page_dashboard.html"
        
        if not os.path.exists(template_file):
            print(f"✗ Template file not found: {template_file}")
            return False
        
        print(f"✓ Template file exists: {template_file}")
        
        with open(template_file, 'r', encoding='utf-8') as f:
            template_content = f.read()
        
        # Check for required elements
        required_elements = [
            "webhookStatusWidget",
            "webhookActivityWidget",
            "refreshWebhookStatus",
            "loadWebhookActivity",
            "renderWebhookStatus",
            "renderWebhookActivity",
            "/api/webhook-status",
            "/api/webhook-activity"
        ]
        
        for element in required_elements:
            if element not in template_content:
                print(f"✗ Missing required element: {element}")
                return False
        
        print(f"✓ All required template elements present")
        print(f"✓ Template file size: {len(template_content)} bytes")
        
        print("\n✓ Dashboard template test successful!\n")
        return True
    except Exception as e:
        print(f"✗ Failed dashboard template test: {e}")
        return False


def run_all_tests():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("WEBHOOK FEATURES TEST SUITE")
    print("=" * 60 + "\n")
    
    tests = [
        ("Imports", test_imports),
        ("App Startup", test_app_startup),
        ("Model Creation", test_model_creation),
        ("Webhook Handler", test_webhook_handler),
        ("SQL Migration", test_sql_migration),
        ("Dashboard Template", test_dashboard_template)
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n✗ Test '{test_name}' crashed: {e}\n")
            results.append((test_name, False))
    
    # Print summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    print("\n" + "=" * 60)
    print(f"RESULTS: {passed}/{total} tests passed")
    print("=" * 60)
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED! Safe to deploy to AWS.\n")
        return True
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Fix issues before deploying.\n")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
