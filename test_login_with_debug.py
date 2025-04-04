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

def test_tenant_admin_login_with_debug():
    """
    Test the tenant admin login API endpoint with detailed error reporting.
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
        
        # For 500 errors, try to extract the error message from the HTML response
        if response.status_code == 500:
            logger.error("Server error (500) detected")
            
            # Try to extract the error message from the HTML
            html_content = response.text
            
            # Look for the exception message
            import re
            exception_match = re.search(r'<pre class="exception_value">(.*?)</pre>', html_content, re.DOTALL)
            if exception_match:
                exception_value = exception_match.group(1)
                logger.error(f"Exception value: {exception_value}")
            
            # Look for the traceback
            traceback_match = re.search(r'<div id="traceback">(.*?)</div>', html_content, re.DOTALL)
            if traceback_match:
                traceback_html = traceback_match.group(1)
                # Extract frames from traceback
                frames = re.findall(r'<li class="frame.*?">(.*?)</li>', traceback_html, re.DOTALL)
                if frames:
                    logger.error("Traceback (most recent call last):")
                    for i, frame in enumerate(frames):
                        # Extract file and line info
                        file_match = re.search(r'<div class="location">(.*?)</div>', frame, re.DOTALL)
                        if file_match:
                            location = file_match.group(1).strip()
                            logger.error(f"  File {location}")
                        
                        # Extract code context
                        code_match = re.search(r'<div class="context".*?>(.*?)</div>', frame, re.DOTALL)
                        if code_match:
                            code_context = code_match.group(1).strip()
                            # Clean up HTML tags
                            code_context = re.sub(r'<.*?>', '', code_context)
                            logger.error(f"    {code_context.strip()}")
        else:
            # For non-500 responses, log the full response content
            logger.info(f"Response content: {response.text}")
            
            # Try to parse JSON response
            try:
                response_data = response.json()
                logger.info(f"Parsed response: {json.dumps(response_data, indent=2)}")
            except json.JSONDecodeError:
                logger.warning("Response is not valid JSON")
        
        return response.status_code, response.text
    except Exception as e:
        logger.error(f"Error making API request: {str(e)}")
        return None, str(e)

if __name__ == "__main__":
    logger.info("=" * 50)
    logger.info("Testing tenant admin login API with debug")
    logger.info("=" * 50)
    
    status_code, response_text = test_tenant_admin_login_with_debug()
    
    logger.info("=" * 50)
    logger.info(f"Test completed with status code: {status_code}")
    logger.info("=" * 50)
