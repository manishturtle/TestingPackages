"""
Script to create tenant admin users for existing tenants that don't have one
"""
import os
import django
import logging
import sys
import getpass

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'KeyProductSettings.settings')
django.setup()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import models after Django setup
from django.db import connection
from ecomm_superadmin.models import Client, Domain
from django.contrib.auth.hashers import make_password
from django.utils.crypto import get_random_string

def create_tenant_admin(tenant, admin_email=None, admin_password=None, admin_first_name=None, admin_last_name=None):
    """
    Create a tenant admin user for a tenant
    
    Args:
        tenant (Client): The tenant to create an admin for
        admin_email (str, optional): Email for the admin user
        admin_password (str, optional): Password for the admin user
        admin_first_name (str, optional): First name for the admin user
        admin_last_name (str, optional): Last name for the admin user
    
    Returns:
        bool: True if admin was created, False otherwise
    """
    # Set connection to tenant schema
    connection.set_tenant(tenant)
    
    try:
        # Import tenant-specific models
        from ecomm_tenant.ecomm_tenant_admins.models import TenantUser, UserProfile, Role, UserRole
        
        # Check if tenant admin already exists
        existing_admins = TenantUser.objects.filter(is_staff=True)
        if existing_admins.exists():
            logger.info(f"Tenant {tenant.name} already has {existing_admins.count()} admin(s)")
            
            # List existing admins
            for admin in existing_admins:
                logger.info(f"  - {admin.email} (is_staff={admin.is_staff})")
            
            # Ask if we should create another admin
            if admin_email is None:
                create_another = input("Create another admin? (y/n): ").lower() == 'y'
                if not create_another:
                    return False
        
        # Get admin details if not provided
        if admin_email is None:
            admin_email = input("Enter admin email: ")
        
        if admin_first_name is None:
            admin_first_name = input("Enter admin first name: ")
        
        if admin_last_name is None:
            admin_last_name = input("Enter admin last name: ")
        
        if admin_password is None:
            admin_password = getpass.getpass("Enter admin password (leave empty to generate): ")
            if not admin_password:
                admin_password = get_random_string(length=12)
                logger.info(f"Generated password: {admin_password}")
        
        # Create the tenant admin user
        admin_user = TenantUser.objects.create_user(
            username=admin_email,
            email=admin_email,
            password=admin_password,  # create_user will hash the password
            first_name=admin_first_name,
            last_name=admin_last_name,
            is_staff=True,  # This makes them a tenant admin
            is_active=True
        )
        
        logger.info(f"Created tenant admin user: {admin_user.email} with is_staff={admin_user.is_staff}")
        
        # Create a UserProfile for the admin user
        user_profile = UserProfile.objects.create(
            user=admin_user,
            is_tenant_admin=True,
            is_company_admin=True,
            is_email_verified=True  # Auto-verify the tenant admin
        )
        
        logger.info(f"Created user profile with is_tenant_admin={user_profile.is_tenant_admin}")
        
        # Create tenant admin role if it doesn't exist
        admin_role, created = Role.objects.get_or_create(
            name='tenant_admin',
            defaults={
                'description': 'Tenant administrator with full access to tenant resources'
            }
        )
        
        # Assign the admin role to the user
        user_role = UserRole.objects.create(
            user=admin_user,
            role=admin_role
        )
        
        logger.info(f"Created tenant admin role and assigned to user: {user_role.role.name}")
        
        # Verify that the user was created correctly
        verification_user = TenantUser.objects.get(email=admin_email)
        logger.info(f"Verification - User exists: {verification_user is not None}")
        logger.info(f"Verification - User is_staff: {verification_user.is_staff}")
        logger.info(f"Verification - User is_active: {verification_user.is_active}")
        
        # Verify that the user can be authenticated
        from django.contrib.auth import authenticate
        auth_user = authenticate(username=admin_email, password=admin_password)
        if auth_user:
            logger.info(f"Verification - User can be authenticated: True")
        else:
            logger.warning(f"Verification - User can be authenticated: False")
        
        # Log the credentials
        logger.info(f"Tenant admin credentials - Email: {admin_email}, Password: {admin_password}")
        
        return True
    
    except Exception as e:
        logger.error(f"Error creating tenant admin user: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Reset to public schema
        connection.set_schema_to_public()

def fix_tenant_admins(tenant_slug=None):
    """
    Create tenant admin users for tenants that don't have one
    
    Args:
        tenant_slug (str, optional): Tenant slug to fix. If None, check all tenants.
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
        tenants = Client.objects.exclude(schema_name='public')
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
        
        # Create tenant admin user
        create_tenant_admin(tenant)
    
    logger.info("Tenant admin creation completed")

if __name__ == "__main__":
    # Get tenant slug from command line arguments or use None to process all tenants
    tenant_slug = sys.argv[1] if len(sys.argv) > 1 else None
    
    # Fix tenant admins
    fix_tenant_admins(tenant_slug)
