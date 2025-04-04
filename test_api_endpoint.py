import requests
import json
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_api_endpoint():
    """
    Test the tenant admin API endpoint for user existence check.
    """
    try:
        # Test email
        test_email = "ankit@quickassist.co.in"
        
        # API endpoint URL
        api_url = "http://localhost:8000/api/qa/tenant-admin/auth/check-user/"
        
        # Headers
        headers = {
            'Content-Type': 'application/json',
            'X-Tenant-Admin': 'true',
            'X-Tenant-Name': 'qa'
        }
        
        # Payload
        payload = {
            'email': test_email
        }
        
        logger.info(f"Making API request to: {api_url}")
        logger.info(f"Headers: {headers}")
        logger.info(f"Payload: {payload}")
        
        response = requests.post(api_url, json=payload, headers=headers)
        logger.info(f"Response status code: {response.status_code}")
        logger.info(f"Response content: {response.text}")
        
        # Parse the response
        if response.status_code == 200:
            logger.info("API call successful!")
            try:
                data = response.json()
                logger.info(f"Parsed response: {data}")
            except json.JSONDecodeError:
                logger.error("Failed to parse JSON response")
        else:
            logger.error(f"API call failed with status code: {response.status_code}")
    
    except Exception as e:
        logger.error(f"Error making API request: {str(e)}")

if __name__ == "__main__":
    test_api_endpoint()
