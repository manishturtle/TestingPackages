"""
Signal handlers for the ecomm_superadmin app
"""
import logging
from django.db import connection
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.management import call_command
from .models import Tenant, Domain

logger = logging.getLogger(__name__)

@receiver(post_save, sender=Tenant)
def create_tenant_schema(sender, instance, created, **kwargs):
    """
    Signal handler to create a tenant schema and run migrations when a new Tenant is created
    """
    if created:
        logger.info(f"New tenant created: {instance.name} (schema: {instance.schema_name})")
        
        # Create Domain entry if it doesn't exist
        try:
            domain, domain_created = Domain.objects.get_or_create(
                tenant=instance,
                domain='localhost',
                defaults={'folder': instance.url_suffix}
            )
            if domain_created:
                logger.info(f"Created Domain entry for tenant: {instance.name} with folder: {instance.url_suffix}")
            else:
                logger.info(f"Domain entry already exists for tenant: {instance.name}")
        except Exception as e:
            logger.error(f"Error creating Domain entry: {str(e)}")
        
        # Store the current schema
        current_schema = connection.schema_name
        
        try:
            # Set connection to tenant schema
            connection.set_tenant(instance)
            
            # Run migrations for the tenant schema
            logger.info(f"Running migrations for tenant: {instance.name}")
            call_command('migrate', schema_name=instance.schema_name, interactive=False)
            logger.info(f"Successfully migrated schema '{instance.schema_name}'")
        except Exception as e:
            logger.error(f"Error setting up tenant schema: {str(e)}")
        finally:
            # Restore the original schema
            if current_schema == 'public':
                connection.set_schema_to_public()
            else:
                try:
                    tenant = Tenant.objects.get(schema_name=current_schema)
                    connection.set_tenant(tenant)
                except Tenant.DoesNotExist:
                    connection.set_schema_to_public()
