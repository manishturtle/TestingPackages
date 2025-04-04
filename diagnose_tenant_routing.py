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
from ecomm_superadmin.models import Domain, Client
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def diagnose_tenant_routing():
    """
    Diagnose issues with tenant routing for subfolder-based multi-tenancy.
    """
    try:
        # Make sure we're in the public schema
        connection.set_schema_to_public()
        
        # 1. Check Django Tenants Configuration
        logger.info("=== Checking Django Tenants Configuration ===")
        logger.info(f"TENANT_MODEL: {settings.TENANT_MODEL}")
        logger.info(f"TENANT_DOMAIN_MODEL: {settings.TENANT_DOMAIN_MODEL}")
        logger.info(f"TENANT_SUBFOLDER_PREFIX: {settings.TENANT_SUBFOLDER_PREFIX}")
        logger.info(f"TENANT_SUBFOLDER_URLS: {getattr(settings, 'TENANT_SUBFOLDER_URLS', False)}")
        
        # 2. Check Domain Model Configuration
        logger.info("\n=== Checking Domain Model Configuration ===")
        domains = Domain.objects.all()
        logger.info(f"Found {domains.count()} domain records:")
        for domain in domains:
            tenant_name = domain.tenant.name if domain.tenant else "None"
            tenant_schema = domain.tenant.schema_name if domain.tenant else "None"
            folder_display = domain.folder if domain.folder else "NULL"
            logger.info(f"Domain: {domain.domain}, Folder: {folder_display}, Tenant: {tenant_name} (Schema: {tenant_schema})")
        
        # 3. Check if the 'qa' tenant exists
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
        
        # 4. Check if there's a domain record with folder='qa'
        logger.info("\n=== Checking Domain with folder='qa' ===")
        try:
            qa_domain = Domain.objects.get(folder='qa')
            logger.info(f"Found domain with folder='qa': {qa_domain.domain}/{qa_domain.folder}")
            logger.info(f"Tenant: {qa_domain.tenant.name} (Schema: {qa_domain.tenant.schema_name})")
        except Domain.DoesNotExist:
            logger.error("No domain found with folder='qa'")
        
        # 5. Fix Domain Model if needed
        logger.info("\n=== Fixing Domain Model ===")
        try:
            # Get the 'qa' tenant
            qa_tenant = Client.objects.get(schema_name='qa')
            
            # Check if there's a domain record with folder='qa'
            try:
                qa_domain = Domain.objects.get(folder='qa')
                logger.info(f"Domain with folder='qa' already exists: {qa_domain.domain}/{qa_domain.folder}")
                
                # Make sure it's associated with the 'qa' tenant
                if qa_domain.tenant != qa_tenant:
                    qa_domain.tenant = qa_tenant
                    qa_domain.save()
                    logger.info(f"Updated domain {qa_domain.domain}/{qa_domain.folder} to be associated with 'qa' tenant")
            except Domain.DoesNotExist:
                # Create a new domain record with folder='qa'
                qa_domain = Domain.objects.create(
                    domain='localhost',
                    folder='qa',
                    tenant=qa_tenant,
                    is_primary=True
                )
                logger.info(f"Created new domain with folder='qa': {qa_domain.domain}/{qa_domain.folder}")
        except Client.DoesNotExist:
            logger.error("'qa' tenant not found")
        
        # 6. Verify Domain Model after fixes
        logger.info("\n=== Verifying Domain Model ===")
        domains = Domain.objects.all()
        logger.info(f"Found {domains.count()} domain records:")
        for domain in domains:
            tenant_name = domain.tenant.name if domain.tenant else "None"
            tenant_schema = domain.tenant.schema_name if domain.tenant else "None"
            folder_display = domain.folder if domain.folder else "NULL"
            logger.info(f"Domain: {domain.domain}, Folder: {folder_display}, Tenant: {tenant_name} (Schema: {tenant_schema})")
        
        # 7. Test tenant routing directly using the database connection
        logger.info("\n=== Testing Tenant Routing ===")
        try:
            # Get the domain with folder='qa'
            qa_domain = Domain.objects.get(folder='qa')
            
            # Set the tenant on the connection
            connection.set_tenant(qa_domain.tenant)
            
            # Check the current schema
            logger.info(f"Current schema: {connection.schema_name}")
            
            # Reset to public schema
            connection.set_schema_to_public()
        except Domain.DoesNotExist:
            logger.error("No domain found with folder='qa'")
        
        logger.info("\nDiagnostic completed.")
    
    except Exception as e:
        logger.error(f"Error during diagnostic: {str(e)}")

if __name__ == "__main__":
    diagnose_tenant_routing()
