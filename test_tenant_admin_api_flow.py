import requests
import json
import logging
import jwt

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# API base URL
BASE_URL = "http://localhost:8000"
TENANT = "qa"  # The tenant to test

# Test credentials
EMAIL = "ankit@quickassist.co.in"
PASSWORD = "India@123"

# Test user data
TEST_USER_DATA = {
    "email": "test_user2@example.com",
    "first_name": "Test",
    "last_name": "User",
    "user_type": "internal"
}

def decode_jwt_token(token):
    """Decode the JWT token without verification to inspect its contents"""
    try:
        # Decode without verification just to see the payload
        decoded = jwt.decode(token, options={"verify_signature": False})
        return decoded
    except Exception as e:
        logger.error(f"Error decoding token: {e}")
        return None

def login_tenant_admin():
    """Login as tenant admin and return the JWT token"""
    url = f"{BASE_URL}/api/{TENANT}/tenant-admin/auth/login/"
    
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Tenant-Name": TENANT,
        "X-Tenant-Admin": "true"
    }
    
    data = {
        "email": EMAIL,
        "password": PASSWORD
    }
    
    logger.info(f"Attempting login to {url} with email {EMAIL}")
    logger.info(f"Request headers: {headers}")
    logger.info(f"Request data: {data}")
    
    response = requests.post(url, json=data, headers=headers)
    
    logger.info(f"Response status code: {response.status_code}")
    logger.info(f"Response headers: {dict(response.headers)}")
    
    if response.status_code != 200:
        logger.error(f"Login failed with status code {response.status_code}")
        logger.error(f"Response: {response.text}")
        return None
    
    response_data = response.json()
    logger.info("Login successful")
    logger.info(f"Response data: {json.dumps(response_data, indent=2)}")
    
    # Extract the access token
    if "token" in response_data and "access" in response_data["token"]:
        token = response_data["token"]["access"]
        logger.info(f"Access token received: {token[:20]}...")
        
        # Decode and inspect the token
        decoded_token = decode_jwt_token(token)
        if decoded_token:
            logger.info(f"Decoded token: {json.dumps(decoded_token, indent=2)}")
            
        return token
    else:
        logger.error(f"Unexpected token format: {response_data}")
        return None

def create_tenant_user(token):
    """Create a new tenant user using the provided token"""
    url = f"{BASE_URL}/api/{TENANT}/tenant-admin/users/"
    
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
        "X-Tenant-Name": TENANT,
        "X-Tenant-Admin": "true"
    }
    
    logger.info(f"Creating tenant user at {url}")
    logger.info(f"User data: {TEST_USER_DATA}")
    logger.info(f"Request headers: {headers}")
    
    response = requests.post(url, json=TEST_USER_DATA, headers=headers)
    
    logger.info(f"Response status code: {response.status_code}")
    logger.info(f"Response headers: {dict(response.headers)}")
    
    if response.status_code >= 200 and response.status_code < 300:
        logger.info(f"User created successfully: {response.json()}")
        return True
    else:
        logger.error(f"User creation failed with status code {response.status_code}")
        logger.error(f"Response: {response.text}")
        return False

def test_token_validation(token):
    """Test if the token is valid by making a GET request to the users endpoint"""
    url = f"{BASE_URL}/api/{TENANT}/tenant-admin/users/"
    
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
        "X-Tenant-Name": TENANT,
        "X-Tenant-Admin": "true"
    }
    
    logger.info(f"Testing token validation at {url}")
    logger.info(f"Request headers: {headers}")
    
    response = requests.get(url, headers=headers)
    
    logger.info(f"Response status code: {response.status_code}")
    
    if response.status_code >= 200 and response.status_code < 300:
        logger.info("Token is valid")
        return True
    else:
        logger.error(f"Token validation failed with status code {response.status_code}")
        logger.error(f"Response: {response.text}")
        return False

def main():
    """Main test function"""
    logger.info("Starting tenant admin API test")
    
    # Step 1: Login as tenant admin
    token = login_tenant_admin()
    if not token:
        logger.error("Login failed, cannot proceed with user creation")
        return
    
    # Step 2: Test token validation
    if not test_token_validation(token):
        logger.error("Token validation failed, cannot proceed with user creation")
        return
    
    # Step 3: Create a tenant user
    success = create_tenant_user(token)
    if success:
        logger.info("Test completed successfully")
    else:
        logger.error("Test failed")

if __name__ == "__main__":
    main()
