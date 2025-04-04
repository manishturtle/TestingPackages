#!/usr/bin/env python
"""
Test script to diagnose tenant admin login issues.
This script tests the URL patterns and routing for tenant admin authentication.
"""

import os
import sys
import requests
import json
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration
BASE_URL = "http://localhost:8000"
TENANT_SLUG = "vb"  # Replace with your tenant slug
TEST_EMAIL = "admin@example.com"  # Replace with a valid tenant admin email
TEST_PASSWORD = "admin123"  # Replace with the correct password

def test_tenant_admin_check_user():
    """Test the check-user endpoint for tenant admin login."""
    # Test URL format: /api/{tenant_slug}/tenant-admin/auth/check-user/
    url = f"{BASE_URL}/api/{TENANT_SLUG}/tenant-admin/auth/check-user/"
    
    headers = {
        'Content-Type': 'application/json',
        'X-Tenant-Admin': 'true',
        'X-Tenant-Name': TENANT_SLUG
    }
    
    data = {
        'email': TEST_EMAIL
    }
    
    logger.info(f"Testing tenant admin check-user endpoint: {url}")
    logger.info(f"Headers: {headers}")
    logger.info(f"Data: {data}")
    
    try:
        response = requests.post(url, json=data, headers=headers)
        logger.info(f"Status code: {response.status_code}")
        logger.info(f"Response: {response.text}")
        
        if response.status_code == 200:
            logger.info("✅ Tenant admin check-user endpoint is working!")
            return True
        else:
            logger.error("❌ Tenant admin check-user endpoint failed!")
            return False
    except Exception as e:
        logger.error(f"❌ Error testing tenant admin check-user endpoint: {e}")
        return False

def test_tenant_admin_login():
    """Test the login endpoint for tenant admin login."""
    # Test URL format: /api/{tenant_slug}/tenant-admin/auth/login/
    url = f"{BASE_URL}/api/{TENANT_SLUG}/tenant-admin/auth/login/"
    
    headers = {
        'Content-Type': 'application/json',
        'X-Tenant-Admin': 'true',
        'X-Tenant-Name': TENANT_SLUG
    }
    
    data = {
        'email': TEST_EMAIL,
        'password': TEST_PASSWORD
    }
    
    logger.info(f"Testing tenant admin login endpoint: {url}")
    logger.info(f"Headers: {headers}")
    logger.info(f"Data: {data}")
    
    try:
        response = requests.post(url, json=data, headers=headers)
        logger.info(f"Status code: {response.status_code}")
        logger.info(f"Response: {response.text}")
        
        if response.status_code == 200:
            logger.info("✅ Tenant admin login endpoint is working!")
            return True
        else:
            logger.error("❌ Tenant admin login endpoint failed!")
            return False
    except Exception as e:
        logger.error(f"❌ Error testing tenant admin login endpoint: {e}")
        return False

def test_tenant_url_patterns():
    """Test different URL patterns to identify which ones work."""
    patterns = [
        f"{BASE_URL}/api/{TENANT_SLUG}/tenant-admin/auth/check-user/",
        f"{BASE_URL}/{TENANT_SLUG}/api/tenant-admin/auth/check-user/",
        f"{BASE_URL}/{TENANT_SLUG}/tenant-admin/api/auth/check-user/"
    ]
    
    headers = {
        'Content-Type': 'application/json',
        'X-Tenant-Admin': 'true',
        'X-Tenant-Name': TENANT_SLUG
    }
    
    data = {
        'email': TEST_EMAIL
    }
    
    logger.info("Testing different URL patterns for tenant admin check-user endpoint")
    
    for url in patterns:
        logger.info(f"Testing URL pattern: {url}")
        try:
            response = requests.post(url, json=data, headers=headers)
            logger.info(f"Status code: {response.status_code}")
            logger.info(f"Response: {response.text}")
            
            if response.status_code == 200:
                logger.info(f"✅ URL pattern works: {url}")
            else:
                logger.error(f"❌ URL pattern failed: {url}")
        except Exception as e:
            logger.error(f"❌ Error testing URL pattern {url}: {e}")

def test_tenant_existence():
    """Test if the tenant exists in the database."""
    url = f"{BASE_URL}/platform-admin/api/clients/"
    
    headers = {
        'Content-Type': 'application/json',
        'X-Platform-Admin': 'true'
    }
    
    logger.info(f"Testing tenant existence: {TENANT_SLUG}")
    
    try:
        response = requests.get(url, headers=headers)
        logger.info(f"Status code: {response.status_code}")
        
        if response.status_code == 200:
            clients = response.json()
            logger.info(f"Found {len(clients)} clients")
            
            tenant_found = False
            for client in clients:
                if client.get('url_suffix') == TENANT_SLUG or client.get('schema_name') == TENANT_SLUG:
                    tenant_found = True
                    logger.info(f"✅ Tenant found: {client}")
                    break
            
            if not tenant_found:
                logger.error(f"❌ Tenant not found: {TENANT_SLUG}")
        else:
            logger.error("❌ Failed to get clients list")
    except Exception as e:
        logger.error(f"❌ Error testing tenant existence: {e}")

if __name__ == "__main__":
    logger.info("Starting tenant admin login tests")
    
    # Test if the tenant exists
    test_tenant_existence()
    
    # Test the check-user endpoint
    check_user_result = test_tenant_admin_check_user()
    
    # Test different URL patterns
    test_tenant_url_patterns()
    
    # Test the login endpoint if check-user passed
    if check_user_result:
        test_tenant_admin_login()
    
    logger.info("Tenant admin login tests completed")
