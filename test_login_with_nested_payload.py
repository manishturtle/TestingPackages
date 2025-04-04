import os
import sys
import django
import requests
import json
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_tenant_admin_login_with_nested_payload():
    """
    Test the tenant admin login API endpoint with the nested payload structure.
    """
    # Test parameters
    tenant_slug = "qa"
    tenant_admin_email = "ankit@quickassist.co.in"
    tenant_admin_password = "India@123"
    api_url = f"http://localhost:8000/api/{tenant_slug}/tenant-admin/auth/login/"
    
    # Make the API request
    logger.info(f"Testing API endpoint: {api_url}")
    logger.info(f"Testing with tenant admin email: {tenant_admin_email}")
    
    headers = {
        'Content-Type': 'application/json',
        'X-Tenant-Admin': 'true',
        'X-Tenant-Name': tenant_slug
    }
    
    # Create the nested payload structure that matches what the frontend is sending
    payload = {
        'email': {
            'email': tenant_admin_email,
            'password': tenant_admin_password
        },
        'password': tenant_slug
    }
    
    logger.info(f"Using nested payload structure: {json.dumps(payload, indent=2)}")
    
    try:
        response = requests.post(api_url, headers=headers, json=payload)
        logger.info(f"Response status code: {response.status_code}")
        
        # For successful responses, log the parsed JSON
        if response.status_code in [200, 202]:
            try:
                response_data = response.json()
                logger.info(f"Login successful! Response contains token: {'token' in response_data}")
                logger.info(f"User ID: {response_data.get('user_id')}")
                
                # Check if we got a token
                if 'token' in response_data:
                    access_token = response_data['token'].get('access')
                    logger.info(f"Access token received (first 20 chars): {access_token[:20]}...")
                    return True, response_data
                else:
                    logger.warning("No token in response")
                    return False, response_data
            except json.JSONDecodeError:
                logger.error("Failed to parse response as JSON")
                logger.error(f"Raw response: {response.text}")
                return False, None
        else:
            # For error responses, log the full response
            logger.error(f"API call failed with status code: {response.status_code}")
            logger.error(f"Response content: {response.text}")
            return False, None
    except Exception as e:
        logger.error(f"Error making API request: {str(e)}")
        return False, None

if __name__ == "__main__":
    logger.info("=" * 50)
    logger.info("Testing tenant admin login API with nested payload")
    logger.info("=" * 50)
    
    success, response_data = test_tenant_admin_login_with_nested_payload()
    
    if success:
        logger.info("Tenant admin login API test PASSED")
        logger.info("User can now access the dashboard")
    else:
        logger.error("Tenant admin login API test FAILED")
    
    logger.info("=" * 50)
