import os
import django
import sys
import json

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

def diagnose_tenant_admin():
    """
    Diagnose issues with tenant admin setup and routing.
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
        
        # Get all domains
        domains = Domain.objects.all()
        logger.info(f"Found {domains.count()} domain records:")
        for domain in domains:
            tenant_name = domain.tenant.name if domain.tenant else "None"
            folder_display = domain.folder if domain.folder else "NULL"
            logger.info(f"Domain: {domain.domain}, Folder: {folder_display}, Tenant: {tenant_name}")
        
        # 2. Check tenant routing for 'qa' tenant
        logger.info("\n=== Checking tenant routing for 'qa' tenant ===")
        try:
            qa_tenant = Client.objects.get(schema_name='qa')
            logger.info(f"Found 'qa' tenant: {qa_tenant.name} (schema: {qa_tenant.schema_name})")
            
            # Check if there's a domain record for the 'qa' tenant
            qa_domains = Domain.objects.filter(tenant=qa_tenant)
            logger.info(f"Found {qa_domains.count()} domain records for 'qa' tenant:")
            for domain in qa_domains:
                folder_display = domain.folder if domain.folder else "NULL"
                logger.info(f"Domain: {domain.domain}, Folder: {folder_display}")
                
                # Construct the expected URL
                if folder_display and folder_display != "NULL":
                    expected_url = f"http://{domain.domain}/{settings.TENANT_SUBFOLDER_PREFIX}/{folder_display}/tenant-admin/"
                    logger.info(f"Expected URL for tenant admin: {expected_url}")
        except Client.DoesNotExist:
            logger.error("'qa' tenant not found")
        
        # 3. Check user existence in 'qa' tenant schema
        logger.info("\n=== Checking user existence in 'qa' tenant schema ===")
        try:
            qa_tenant = Client.objects.get(schema_name='qa')
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
        
        # 4. Test the tenant admin API endpoint
        logger.info("\n=== Testing tenant admin API endpoint ===")
        logger.info("To test the tenant admin API endpoint, you would need to make an HTTP request to:")
        logger.info("http://localhost:8000/api/qa/tenant-admin/auth/check-user/")
        logger.info("with the following payload: {'email': 'ankit@quickassist.co.in'}")
        logger.info("and the following headers: {'X-Tenant-Admin': 'true', 'X-Tenant-Name': 'qa'}")
        
        logger.info("\nDiagnostic completed successfully.")
    
    except Exception as e:
        logger.error(f"Error during diagnostic: {str(e)}")

if __name__ == "__main__":
    diagnose_tenant_admin()
