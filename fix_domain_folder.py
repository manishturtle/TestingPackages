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

def fix_domain_folder():
    """
    Fix the Domain model by ensuring the folder field is correctly set for the 'qa' tenant.
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
        
        # Get the 'qa' tenant
        try:
            qa_tenant = Client.objects.get(schema_name='qa')
            logger.info(f"Found tenant with schema_name 'qa': {qa_tenant.name}")
            
            # Check if this tenant has any domains
            qa_domains = Domain.objects.filter(tenant=qa_tenant)
            logger.info(f"Found {qa_domains.count()} domains for tenant '{qa_tenant.name}':")
            for domain in qa_domains:
                folder_display = domain.folder if domain.folder else "NULL"
                logger.info(f"Domain: {domain.domain}, Folder: {folder_display}")
                
                # Update the folder field if it's not already set
                if domain.folder != 'qa':
                    domain.folder = 'qa'
                    domain.save()
                    logger.info(f"Updated domain {domain.domain} with folder 'qa'")
            
            # If no domains found for the 'qa' tenant, create one
            if not qa_domains.exists():
                domain = Domain.objects.create(
                    domain='localhost',
                    folder='qa',
                    tenant=qa_tenant,
                    is_primary=True
                )
                logger.info(f"Created new domain for tenant '{qa_tenant.name}': localhost/qa")
        
        except Client.DoesNotExist:
            logger.error("No tenant found with schema_name 'qa'")
        
        # Check the results
        logger.info("\nAfter updates:")
        domains = Domain.objects.all()
        logger.info(f"Found {domains.count()} domain records:")
        for domain in domains:
            tenant_name = domain.tenant.name if domain.tenant else "None"
            tenant_schema = domain.tenant.schema_name if domain.tenant else "None"
            folder_display = domain.folder if domain.folder else "NULL"
            logger.info(f"Domain: {domain.domain}, Folder: {folder_display}, Tenant: {tenant_name} (Schema: {tenant_schema})")
        
        logger.info("Domain folder fix completed.")
    
    except Exception as e:
        logger.error(f"Error fixing domain folder: {str(e)}")

if __name__ == "__main__":
    fix_domain_folder()
