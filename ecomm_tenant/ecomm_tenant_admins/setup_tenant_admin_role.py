from django.core.management.base import BaseCommand
from authentication.models import Role, Permission, RolePermission
from django.db import transaction

class Command(BaseCommand):
    help = 'Sets up the tenant_admin role with appropriate permissions'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Setting up tenant_admin role...'))
        
        with transaction.atomic():
            # Create the tenant_admin role if it doesn't exist
            role, created = Role.objects.get_or_create(
                name='tenant_admin',
                defaults={
                    'description': 'Tenant administrator with full access to tenant resources'
                }
            )
            
            if created:
                self.stdout.write(self.style.SUCCESS('Created tenant_admin role'))
            else:
                self.stdout.write(self.style.SUCCESS('tenant_admin role already exists'))
            
            # Define permissions for tenant_admin
            tenant_permissions = [
                # User management permissions
                {
                    'name': 'View Users',
                    'codename': 'view_user',
                    'description': 'Can view all users in the tenant'
                },
                {
                    'name': 'Add User',
                    'codename': 'add_user',
                    'description': 'Can add new users to the tenant'
                },
                {
                    'name': 'Edit User',
                    'codename': 'change_user',
                    'description': 'Can edit existing users in the tenant'
                },
                {
                    'name': 'Delete User',
                    'codename': 'delete_user',
                    'description': 'Can delete users from the tenant'
                },
                
                # Company management permissions
                {
                    'name': 'View Company',
                    'codename': 'view_company',
                    'description': 'Can view company details'
                },
                {
                    'name': 'Edit Company',
                    'codename': 'change_company',
                    'description': 'Can edit company details'
                },
                
                # Tenant settings permissions
                {
                    'name': 'View Tenant Settings',
                    'codename': 'view_tenant_settings',
                    'description': 'Can view tenant settings'
                },
                {
                    'name': 'Edit Tenant Settings',
                    'codename': 'change_tenant_settings',
                    'description': 'Can edit tenant settings'
                },
                
                # Role management permissions
                {
                    'name': 'View Roles',
                    'codename': 'view_role',
                    'description': 'Can view all roles in the tenant'
                },
                {
                    'name': 'Add Role',
                    'codename': 'add_role',
                    'description': 'Can add new roles to the tenant'
                },
                {
                    'name': 'Edit Role',
                    'codename': 'change_role',
                    'description': 'Can edit existing roles in the tenant'
                },
                {
                    'name': 'Delete Role',
                    'codename': 'delete_role',
                    'description': 'Can delete roles from the tenant'
                },
                
                # Permission management
                {
                    'name': 'Assign Permissions',
                    'codename': 'assign_permissions',
                    'description': 'Can assign permissions to roles'
                },
                
                # User role management
                {
                    'name': 'Assign Roles',
                    'codename': 'assign_roles',
                    'description': 'Can assign roles to users'
                }
            ]
            
            # Create permissions and assign to tenant_admin role
            for perm_data in tenant_permissions:
                permission, created = Permission.objects.get_or_create(
                    codename=perm_data['codename'],
                    defaults={
                        'name': perm_data['name'],
                        'description': perm_data['description']
                    }
                )
                
                if created:
                    self.stdout.write(f'Created permission: {permission.name}')
                
                # Assign permission to role if not already assigned
                role_perm, created = RolePermission.objects.get_or_create(
                    role=role,
                    permission=permission
                )
                
                if created:
                    self.stdout.write(f'Assigned {permission.name} to {role.name}')
            
            self.stdout.write(self.style.SUCCESS('Successfully set up tenant_admin role with all permissions'))
