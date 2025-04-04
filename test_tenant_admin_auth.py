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

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'KeyProductSettings.settings')
django.setup()

from django.db import connection
from ecomm_superadmin.models import Client, Domain, User as SuperadminUser
from django.contrib.auth import get_user_model
from ecomm_tenant.ecomm_tenant_admins.models import UserProfile

def test_tenant_admin_api():
    """
    Test the tenant admin API endpoint for user existence check.
    """
    # Test parameters
    tenant_slug = "qa"
    tenant_admin_email = "ankit@quickassist.co.in"
    api_url = f"http://localhost:8000/api/{tenant_slug}/tenant-admin/auth/check-user/"
    
    # Make the API request
    logger.info(f"Testing API endpoint: {api_url}")
    logger.info(f"Testing with tenant admin email: {tenant_admin_email}")
    
    headers = {
        'Content-Type': 'application/json',
        'X-Tenant-Admin': 'true',
        'X-Tenant-Name': tenant_slug
    }
    
    payload = {
        'email': tenant_admin_email
    }
    
    try:
        response = requests.post(api_url, headers=headers, json=payload)
        logger.info(f"Response status code: {response.status_code}")
        logger.info(f"Response content: {response.text}")
        
        if response.status_code == 200:
            logger.info("API call successful!")
            return True
        else:
            logger.error(f"API call failed with status code: {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"Error making API request: {str(e)}")
        return False

def verify_tenant_admin_setup():
    """
    Verify that the tenant admin user is properly set up in the tenant schema.
    """
    try:
        # Make sure we're in the public schema
        connection.set_schema_to_public()
        logger.info("Switched to public schema")
        
        # Get the 'qa' tenant
        try:
            qa_tenant = Client.objects.get(schema_name='qa')
            logger.info(f"Found 'qa' tenant: {qa_tenant.name} (schema: {qa_tenant.schema_name})")
            
            # Check if domain with folder='qa' exists
            try:
                domain = Domain.objects.get(folder='qa')
                logger.info(f"Found domain with folder='qa': {domain.domain}, tenant: {domain.tenant.schema_name}")
            except Domain.DoesNotExist:
                logger.error("No domain found with folder='qa'")
                # Create domain with folder='qa'
                domain = Domain(
                    domain='localhost',
                    folder='qa',
                    tenant=qa_tenant,
                    is_primary=True
                )
                domain.save()
                logger.info(f"Created domain with folder='qa' for tenant: {qa_tenant.schema_name}")
            
            # Switch to the 'qa' schema
            connection.set_tenant(qa_tenant)
            logger.info(f"Switched to tenant schema: {connection.schema_name}")
            
            # Get the correct user model for the tenant schema
            User = get_user_model()
            logger.info(f"Using user model: {User.__name__}")
            
            # Check if the tenant admin user exists
            tenant_admin_email = "ankit@quickassist.co.in"
            try:
                user = User.objects.get(email=tenant_admin_email)
                logger.info(f"Found tenant admin user: {user.email} (ID: {user.id})")
                
                # Check if the user has a profile
                try:
                    profile = UserProfile.objects.get(user=user)
                    logger.info(f"Found user profile for {user.email} (ID: {profile.id})")
                    logger.info(f"User is tenant admin: {profile.is_tenant_admin}")
                    
                    # Ensure the user is a tenant admin
                    if not profile.is_tenant_admin:
                        profile.is_tenant_admin = True
                        profile.save()
                        logger.info(f"Updated user profile: is_tenant_admin=True")
                except UserProfile.DoesNotExist:
                    logger.error(f"No user profile found for {user.email}")
                    return False
            except User.DoesNotExist:
                logger.error(f"Tenant admin user not found: {tenant_admin_email}")
                return False
            
            return True
            
        except Client.DoesNotExist:
            logger.error("'qa' tenant not found")
            return False
    
    except Exception as e:
        logger.error(f"Error verifying tenant admin setup: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return False

def main():
    """
    Main function to run the tests.
    """
    logger.info("=" * 50)
    logger.info("Starting tenant admin API tests")
    logger.info("=" * 50)
    
    # Verify tenant admin setup
    logger.info("\nVerifying tenant admin setup...")
    setup_ok = verify_tenant_admin_setup()
    
    if setup_ok:
        logger.info("Tenant admin setup verified successfully")
    else:
        logger.error("Tenant admin setup verification failed")
    
    # Test the API endpoint
    logger.info("\nTesting tenant admin API endpoint...")
    api_ok = test_tenant_admin_api()
    
    if api_ok:
        logger.info("Tenant admin API test passed")
    else:
        logger.error("Tenant admin API test failed")
    
    # Summary
    logger.info("\n" + "=" * 50)
    logger.info("Test Summary")
    logger.info("=" * 50)
    logger.info(f"Tenant admin setup: {'PASS' if setup_ok else 'FAIL'}")
    logger.info(f"Tenant admin API: {'PASS' if api_ok else 'FAIL'}")
    logger.info("=" * 50)

if __name__ == "__main__":
    main()
