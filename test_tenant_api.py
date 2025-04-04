"""
Script to test the Tenant API directly.
This will help diagnose any issues with the API endpoint.
"""
import os
import sys
import django
import requests
import json
from datetime import datetime, date

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'KeyProductSettings.settings')
django.setup()

# Import Django modules
from django.test import Client
from django.urls import reverse
from django.contrib.auth import get_user_model

User = get_user_model()

def test_tenant_api():
    """
    Test the Tenant API endpoint directly using Django's test client.
    """
    print("Testing Tenant API endpoint...")
    
    # Create a test client
    client = Client()
    
    # Get or create a superuser for testing
    try:
        admin_user = User.objects.get(username='admin')
    except User.DoesNotExist:
        admin_user = User.objects.create_superuser(
            username='admin',
            email='admin@example.com',
            password='adminpassword'
        )
        print("Created admin user for testing")
    
    # Log in the admin user
    client.login(username='admin', password='adminpassword')
    
    # Test the tenant list endpoint
    response = client.get('/platform-admin/api/tenants/')
    
    # Print the response
    print(f"Status code: {response.status_code}")
    if response.status_code == 200:
        print("Success! Tenant API is working correctly.")
        try:
            data = response.json()
            print(f"Found {len(data)} tenants:")
            print(json.dumps(data[:2], indent=2))  # Show first 2 tenants
        except Exception as e:
            print(f"Error parsing JSON response: {str(e)}")
            print("Raw response:", response.content)
    else:
        print("Error! Tenant API returned an error.")
        print("Response content:", response.content)
    
    # Test the fixed tenant endpoint if available
    try:
        response = client.get('/platform-admin/api/tenants-fixed/')
        print("\nTesting fixed endpoint:")
        print(f"Status code: {response.status_code}")
        if response.status_code == 200:
            print("Success! Fixed Tenant API is working correctly.")
            try:
                data = response.json()
                print(f"Found {len(data)} tenants:")
                print(json.dumps(data[:2], indent=2))  # Show first 2 tenants
            except Exception as e:
                print(f"Error parsing JSON response: {str(e)}")
                print("Raw response:", response.content)
        else:
            print("Error! Fixed Tenant API returned an error.")
            print("Response content:", response.content)
    except Exception as e:
        print(f"Error testing fixed endpoint: {str(e)}")

if __name__ == "__main__":
    test_tenant_api()
