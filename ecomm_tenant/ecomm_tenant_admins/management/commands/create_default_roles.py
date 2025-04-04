import logging
from django.core.management.base import BaseCommand
from django.db import connection
from ecomm_tenant.ecomm_tenant_admins.models import Role
from tenant_schemas.utils import get_tenant_model

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Creates default roles for all tenant schemas'

    def add_arguments(self, parser):
        parser.add_argument(
            '--tenant-slug',
            type=str,
            help='Specific tenant slug to create roles for (optional)'
        )

    def handle(self, *args, **options):
        tenant_slug = options.get('tenant_slug')
        
        # Define default roles
        default_roles = [
            {
                'name': 'Admin',
                'description': 'Full administrative access to all tenant features'
            },
            {
                'name': 'Manager',
                'description': 'Can manage most tenant resources but cannot modify system settings'
            },
            {
                'name': 'User',
                'description': 'Regular user with basic access to tenant features'
            },
            {
                'name': 'Viewer',
                'description': 'Read-only access to tenant resources'
            }
        ]
        
        Tenant = get_tenant_model()
        
        if tenant_slug:
            # Process a specific tenant
            try:
                tenant = Tenant.objects.get(slug=tenant_slug)
                self.create_roles_for_tenant(tenant, default_roles)
            except Tenant.DoesNotExist:
                self.stdout.write(self.style.ERROR(f'Tenant with slug "{tenant_slug}" does not exist'))
        else:
            # Process all tenants
            tenants = Tenant.objects.all()
            for tenant in tenants:
                self.create_roles_for_tenant(tenant, default_roles)
        
        self.stdout.write(self.style.SUCCESS('Default roles created successfully'))

    def create_roles_for_tenant(self, tenant, default_roles):
        original_schema = connection.schema_name
        
        try:
            # Set schema to tenant schema
            connection.set_schema(tenant.schema_name)
            self.stdout.write(f'Creating roles for tenant: {tenant.name} (schema: {tenant.schema_name})')
            
            # Create default roles
            roles_created = 0
            for role_data in default_roles:
                role, created = Role.objects.get_or_create(
                    name=role_data['name'],
                    defaults={'description': role_data['description']}
                )
                if created:
                    roles_created += 1
                    self.stdout.write(f'  - Created role: {role.name}')
                else:
                    self.stdout.write(f'  - Role already exists: {role.name}')
            
            self.stdout.write(self.style.SUCCESS(f'Created {roles_created} new roles for tenant {tenant.name}'))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error creating roles for tenant {tenant.name}: {str(e)}'))
        finally:
            # Reset schema to original
            connection.set_schema(original_schema)
