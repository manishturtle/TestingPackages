import os
import django
import sys
import json
import requests

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'KeyProductSettings.settings')
django.setup()

from django.db import connection
from django.conf import settings
from ecomm_superadmin.models import Client, Domain, User
from ecomm_tenant.ecomm_tenant_admins.models import UserProfile
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_tenant_admin_api():
    """
    Test the tenant admin API endpoint for user existence check.
    """
    try:
        # Make sure we're in the public schema
        connection.set_schema_to_public()
        
        # 1. Check Domain model configuration
        logger.info("=== Checking Domain model configuration ===")
        logger.info(f"TENANT_MODEL: {settings.TENANT_MODEL}")
        logger.info(f"TENANT_DOMAIN_MODEL: {settings.TENANT_DOMAIN_MODEL}")
        logger.info(f"TENANT_SUBFOLDER_PREFIX: {settings.TENANT_SUBFOLDER_PREFIX}")
        logger.info(f"TENANT_SUBFOLDER_URLS: {getattr(settings, 'TENANT_SUBFOLDER_URLS', False)}")
        
        # 2. Check if the 'qa' tenant exists and has users
        logger.info("\n=== Checking 'qa' tenant and users ===")
        try:
            qa_tenant = Client.objects.get(schema_name='qa')
            logger.info(f"Found 'qa' tenant: {qa_tenant.name} (schema: {qa_tenant.schema_name})")
            
            # Switch to the 'qa' schema
            connection.set_tenant(qa_tenant)
            
            # Check users in the 'qa' schema
            users = User.objects.all()
            logger.info(f"Found {users.count()} users in 'qa' schema:")
            for user in users:
                logger.info(f"User: {user.email}, Staff: {user.is_staff}")
                
                # Check if the user has a profile
                try:
                    profile = UserProfile.objects.get(user=user)
                    logger.info(f"  Profile found: is_tenant_admin={profile.is_tenant_admin}")
                    if profile.company:
                        logger.info(f"  Company: {profile.company.name}, Client: {profile.company.client.schema_name}")
                except UserProfile.DoesNotExist:
                    logger.info(f"  No profile found for user {user.email}")
        except Client.DoesNotExist:
            logger.error("'qa' tenant not found")
        
        # 3. Test the API endpoint directly
        logger.info("\n=== Testing API endpoint directly ===")
        
        # Reset to public schema
        connection.set_schema_to_public()
        
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
        
        try:
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
        
        # 4. Manual check for the user in the 'qa' schema
        logger.info("\n=== Manual check for user in 'qa' schema ===")
        try:
            # Switch to the 'qa' schema
            connection.set_tenant(qa_tenant)
            
            # Try to find the user directly
            try:
                user = User.objects.get(email__iexact=test_email)
                logger.info(f"User found in 'qa' schema: {user.email}")
                
                # Check if the user has a profile
                try:
                    profile = UserProfile.objects.get(user=user)
                    logger.info(f"User profile found: is_tenant_admin={profile.is_tenant_admin}")
                    if profile.company:
                        logger.info(f"Company: {profile.company.name}, Client: {profile.company.client.schema_name}")
                except UserProfile.DoesNotExist:
                    logger.info(f"No profile found for user {user.email}")
            except User.DoesNotExist:
                logger.error(f"User not found in 'qa' schema: {test_email}")
                
                # List all users in the schema
                all_users = User.objects.all()
                logger.info(f"All users in 'qa' schema ({all_users.count()}):")
                for u in all_users:
                    logger.info(f"  {u.email}")
        except Exception as e:
            logger.error(f"Error during manual check: {str(e)}")
        
        logger.info("\nTest completed.")
    
    except Exception as e:
        logger.error(f"Error during test: {str(e)}")

if __name__ == "__main__":
    test_tenant_admin_api()
