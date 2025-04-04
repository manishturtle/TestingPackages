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

def test_tenant_admin_login():
    """
    Test the tenant admin login API endpoint.
    """
    # Test parameters
    tenant_slug = "qa"
    tenant_admin_email = "ankit@quickassist.co.in"
    tenant_admin_password = "Password123!"
    api_url = f"http://localhost:8000/api/{tenant_slug}/tenant-admin/auth/login/"
    
    # Make the API request
    logger.info(f"Testing API endpoint: {api_url}")
    logger.info(f"Testing with tenant admin email: {tenant_admin_email}")
    
    headers = {
        'Content-Type': 'application/json',
        'X-Tenant-Admin': 'true',
        'X-Tenant-Name': tenant_slug
    }
    
    payload = {
        'email': tenant_admin_email,
        'password': tenant_admin_password
    }
    
    try:
        response = requests.post(api_url, headers=headers, json=payload)
        logger.info(f"Response status code: {response.status_code}")
        logger.info(f"Response content: {response.text}")
        
        # Parse the response
        if response.status_code in [200, 202]:
            try:
                response_data = response.json()
                logger.info(f"Parsed response: {json.dumps(response_data, indent=2)}")
                
                # Check if 2FA is required
                if response.status_code == 202 and response_data.get('requires_2fa'):
                    logger.info("2FA is required for login")
                    return True, response_data
                # Check if 2FA setup is needed
                elif response.status_code == 202 and response_data.get('needs_2fa_setup'):
                    logger.info("2FA setup is required for login")
                    return True, response_data
                # Check if login was successful
                elif response.status_code == 200 and response_data.get('token'):
                    logger.info("Login successful, received token")
                    return True, response_data
                else:
                    logger.warning("Unexpected response format")
                    return False, response_data
            except json.JSONDecodeError:
                logger.error("Failed to parse response as JSON")
                return False, None
        else:
            logger.error(f"API call failed with status code: {response.status_code}")
            return False, None
    except Exception as e:
        logger.error(f"Error making API request: {str(e)}")
        return False, None

if __name__ == "__main__":
    logger.info("=" * 50)
    logger.info("Testing tenant admin login API")
    logger.info("=" * 50)
    
    success, response_data = test_tenant_admin_login()
    
    if success:
        logger.info("Tenant admin login API test passed")
        
        # Check response type
        if response_data.get('requires_2fa'):
            logger.info("Next step: Complete 2FA verification")
        elif response_data.get('needs_2fa_setup'):
            logger.info("Next step: Set up 2FA")
        elif response_data.get('token'):
            logger.info("User is authenticated and can access the dashboard")
    else:
        logger.error("Tenant admin login API test failed")
    
    logger.info("=" * 50)
