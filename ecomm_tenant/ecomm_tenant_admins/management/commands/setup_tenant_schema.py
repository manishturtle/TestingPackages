"""
Management command to set up a tenant schema with all required tables
"""
import logging
from django.core.management.base import BaseCommand, CommandError
from django.db import connection
from django_tenants.utils import schema_exists, get_tenant_model, get_public_schema_name
from ecomm_superadmin.models import Tenant, Domain
from django.core.management import call_command

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Sets up a tenant schema with all required tables'

    def add_arguments(self, parser):
        parser.add_argument('--tenant', type=str, help='Tenant schema name or URL suffix')
        parser.add_argument('--all', action='store_true', help='Apply to all tenants')

    def handle(self, *args, **options):
        tenant_identifier = options.get('tenant')
        all_tenants = options.get('all')
        
        if not tenant_identifier and not all_tenants:
            raise CommandError("You must specify either --tenant or --all")
        
        # Get list of tenants to process
        tenants = []
        if all_tenants:
            tenants = Tenant.objects.all()
            self.stdout.write(self.style.SUCCESS(f"Found {len(tenants)} tenants to process"))
        else:
            # Try to find tenant by schema_name or url_suffix
            try:
                tenant = Tenant.objects.get(schema_name=tenant_identifier)
                tenants = [tenant]
            except Tenant.DoesNotExist:
                try:
                    tenant = Tenant.objects.get(url_suffix=tenant_identifier)
                    tenants = [tenant]
                except Tenant.DoesNotExist:
                    try:
                        domain = Domain.objects.get(folder=tenant_identifier)
                        tenants = [domain.tenant]
                    except Domain.DoesNotExist:
                        raise CommandError(f"Tenant with identifier '{tenant_identifier}' not found")
        
        # Process each tenant
        for tenant in tenants:
            self.stdout.write(f"Processing tenant: {tenant.name} (schema: {tenant.schema_name})")
            
            # Check if schema exists
            if not schema_exists(tenant.schema_name):
                self.stdout.write(self.style.WARNING(f"Schema '{tenant.schema_name}' does not exist. Creating..."))
                # Create the schema
                connection.cursor().execute(f"CREATE SCHEMA IF NOT EXISTS {tenant.schema_name}")
            
            # Set connection to tenant schema
            connection.set_tenant(tenant)
            
            # Run migrations for the tenant schema
            self.stdout.write(f"Running migrations for tenant: {tenant.name}")
            try:
                # Run migrations for the tenant apps
                call_command('migrate', schema_name=tenant.schema_name, interactive=False)
                self.stdout.write(self.style.SUCCESS(f"Successfully migrated schema '{tenant.schema_name}'"))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Error migrating schema '{tenant.schema_name}': {str(e)}"))
            
            # Create Domain entry if it doesn't exist
            try:
                domain, created = Domain.objects.get_or_create(
                    tenant=tenant,
                    domain='localhost',
                    defaults={'folder': tenant.url_suffix}
                )
                if created:
                    self.stdout.write(self.style.SUCCESS(f"Created Domain entry for tenant: {tenant.name} with folder: {tenant.url_suffix}"))
                else:
                    self.stdout.write(f"Domain entry already exists for tenant: {tenant.name}")
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Error creating Domain entry: {str(e)}"))
            
            # Reset connection to public schema
            connection.set_schema_to_public()
        
        self.stdout.write(self.style.SUCCESS("Tenant schema setup completed"))
