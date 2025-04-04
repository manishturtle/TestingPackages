"""
Script to fix existing tenant schemas by running migrations for them
"""
import os
import django
import logging
import sys

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'KeyProductSettings.settings')
django.setup()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import models after Django setup
from django.db import connection
from ecomm_superadmin.models import Client, Domain
from django.core.management import call_command

def fix_tenant_schemas(tenant_slug=None):
    """
    Fix tenant schemas by running migrations for them
    
    Args:
        tenant_slug (str, optional): Tenant slug to fix. If None, fix all tenants.
    """
    # Get list of tenants to process
    tenants = []
    if tenant_slug:
        # Try to find tenant by schema_name or url_suffix
        try:
            tenant = Client.objects.get(schema_name=tenant_slug)
            tenants = [tenant]
        except Client.DoesNotExist:
            try:
                tenant = Client.objects.get(url_suffix=tenant_slug)
                tenants = [tenant]
            except Client.DoesNotExist:
                try:
                    domain = Domain.objects.get(folder=tenant_slug)
                    tenants = [domain.tenant]
                except Domain.DoesNotExist:
                    logger.error(f"Tenant with identifier '{tenant_slug}' not found")
                    return
    else:
        tenants = Client.objects.all()
        logger.info(f"Found {len(tenants)} tenants to process")
    
    # Process each tenant
    for tenant in tenants:
        logger.info(f"Processing tenant: {tenant.name} (schema: {tenant.schema_name})")
        
        # Create Domain entry if it doesn't exist
        try:
            domain, created = Domain.objects.get_or_create(
                tenant=tenant,
                domain='localhost',
                defaults={'folder': tenant.url_suffix}
            )
            if created:
                logger.info(f"Created Domain entry for tenant: {tenant.name} with folder: {tenant.url_suffix}")
            else:
                logger.info(f"Domain entry already exists for tenant: {tenant.name}")
        except Exception as e:
            logger.error(f"Error creating Domain entry: {str(e)}")
        
        # Set connection to tenant schema
        connection.set_tenant(tenant)
        
        # Run migrations for the tenant schema
        logger.info(f"Running migrations for tenant: {tenant.name}")
        try:
            # Run migrations for the tenant apps
            call_command('migrate', schema_name=tenant.schema_name, interactive=False)
            logger.info(f"Successfully migrated schema '{tenant.schema_name}'")
        except Exception as e:
            logger.error(f"Error migrating schema '{tenant.schema_name}': {str(e)}")
        
        # Reset connection to public schema
        connection.set_schema_to_public()
    
    logger.info("Tenant schema fix completed")

if __name__ == "__main__":
    # Get tenant slug from command line arguments or use None to process all tenants
    tenant_slug = sys.argv[1] if len(sys.argv) > 1 else None
    
    # Fix tenant schemas
    fix_tenant_schemas(tenant_slug)
