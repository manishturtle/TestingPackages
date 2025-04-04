import os
import django
import sys
import json
import requests
import logging

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'KeyProductSettings.settings')
django.setup()

from django.db import connection
from django.conf import settings
from ecomm_superadmin.models import Domain, Client, User
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Enable debug logging for django_tenants
django_tenants_logger = logging.getLogger('django_tenants')
django_tenants_logger.setLevel(logging.DEBUG)
django_tenants_logger.addHandler(logging.StreamHandler())

def test_tenant_admin_api():
    """
    Test the tenant admin API endpoint with debug logging enabled.
    """
    try:
        # Make sure we're in the public schema
        connection.set_schema_to_public()
        
        # 1. Check Domain Model Configuration
        logger.info("=== Checking Domain Model Configuration ===")
        domains = Domain.objects.all()
        logger.info(f"Found {domains.count()} domain records:")
        for domain in domains:
            tenant_name = domain.tenant.name if domain.tenant else "None"
            tenant_schema = domain.tenant.schema_name if domain.tenant else "None"
            folder_display = domain.folder if domain.folder else "NULL"
            logger.info(f"Domain: {domain.domain}, Folder: {folder_display}, Tenant: {tenant_name} (Schema: {tenant_schema})")
        
        # 2. Check if the 'qa' tenant exists
        logger.info("\n=== Checking 'qa' Tenant ===")
        try:
            qa_tenant = Client.objects.get(schema_name='qa')
            logger.info(f"Found 'qa' tenant: {qa_tenant.name} (schema: {qa_tenant.schema_name})")
            
            # Check if there's a domain record for the 'qa' tenant
            qa_domains = Domain.objects.filter(tenant=qa_tenant)
            logger.info(f"Found {qa_domains.count()} domain records for 'qa' tenant:")
            for domain in qa_domains:
                folder_display = domain.folder if domain.folder else "NULL"
                logger.info(f"Domain: {domain.domain}, Folder: {folder_display}")
        except Client.DoesNotExist:
            logger.error("'qa' tenant not found")
        
        # 3. Test tenant routing directly using the database connection
        logger.info("\n=== Testing Tenant Routing ===")
        try:
            # Get the domain with folder='qa'
            qa_domain = Domain.objects.get(folder='qa')
            
            # Set the tenant on the connection
            connection.set_tenant(qa_domain.tenant)
            
            # Check the current schema
            logger.info(f"Current schema: {connection.schema_name}")
            
            # Check if there are any users in the 'qa' schema
            try:
                users = User.objects.all()
                logger.info(f"Found {users.count()} users in 'qa' schema:")
                for user in users:
                    logger.info(f"User: {user.email}, Staff: {getattr(user, 'is_staff', False)}")
            except Exception as e:
                logger.error(f"Error checking users in 'qa' schema: {str(e)}")
            
            # Reset to public schema
            connection.set_schema_to_public()
        except Domain.DoesNotExist:
            logger.error("No domain found with folder='qa'")
        
        # 4. Test the API endpoint directly
        logger.info("\n=== Testing API Endpoint ===")
        
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
        
        logger.info("\nTest completed.")
    
    except Exception as e:
        logger.error(f"Error during test: {str(e)}")

if __name__ == "__main__":
    test_tenant_admin_api()
