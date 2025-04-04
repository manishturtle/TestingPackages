import os
import django
import sys

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'KeyProductSettings.settings')
django.setup()

from django.db import connection
from ecomm_superadmin.models import Domain, Client
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def check_domains():
    """
    Check the Domain records in the database.
    """
    try:
        # Make sure we're in the public schema
        connection.set_schema_to_public()
        
        # Get all domains
        domains = Domain.objects.all()
        logger.info(f"Found {domains.count()} domain records:")
        for domain in domains:
            tenant_name = domain.tenant.name if domain.tenant else "None"
            tenant_schema = domain.tenant.schema_name if domain.tenant else "None"
            folder_display = domain.folder if domain.folder else "NULL"
            logger.info(f"Domain: {domain.domain}, Folder: {folder_display}, Tenant: {tenant_name} (Schema: {tenant_schema})")
        
        # Check if there's a domain record for the 'qa' folder
        try:
            qa_domain = Domain.objects.get(folder='qa')
            logger.info(f"Found domain with folder 'qa': {qa_domain.domain}/{qa_domain.folder}")
            logger.info(f"Tenant: {qa_domain.tenant.name} (Schema: {qa_domain.tenant.schema_name})")
        except Domain.DoesNotExist:
            logger.error("No domain found with folder 'qa'")
            
            # Check if there's a tenant with schema_name 'qa'
            try:
                qa_tenant = Client.objects.get(schema_name='qa')
                logger.info(f"Found tenant with schema_name 'qa': {qa_tenant.name}")
                
                # Check if this tenant has any domains
                qa_domains = Domain.objects.filter(tenant=qa_tenant)
                logger.info(f"Found {qa_domains.count()} domains for tenant '{qa_tenant.name}':")
                for domain in qa_domains:
                    folder_display = domain.folder if domain.folder else "NULL"
                    logger.info(f"Domain: {domain.domain}, Folder: {folder_display}")
            except Client.DoesNotExist:
                logger.error("No tenant found with schema_name 'qa'")
        
        # Check if there's a domain record with the folder field set to NULL
        null_domains = Domain.objects.filter(folder__isnull=True)
        logger.info(f"Found {null_domains.count()} domains with NULL folder:")
        for domain in null_domains:
            tenant_name = domain.tenant.name if domain.tenant else "None"
            tenant_schema = domain.tenant.schema_name if domain.tenant else "None"
            logger.info(f"Domain: {domain.domain}, Tenant: {tenant_name} (Schema: {tenant_schema})")
        
        logger.info("Domain check completed.")
    
    except Exception as e:
        logger.error(f"Error checking domains: {str(e)}")

if __name__ == "__main__":
    check_domains()
