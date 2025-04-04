import os
import django
import sys

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'KeyProductSettings.settings')
django.setup()

from django.db import connection
from ecomm_superadmin.models import Client, Domain
from django.contrib.auth import get_user_model
from ecomm_tenant.ecomm_tenant_admins.models import UserProfile, Role, UserRole, TenantUser
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def fix_tenant_admin():
    """
    Fix the tenant admin user in the 'qa' tenant.
    """
    try:
        # Make sure we're in the public schema
        connection.set_schema_to_public()
        logger.info("Starting in public schema")
        
        # Get the 'qa' tenant
        try:
            qa_tenant = Client.objects.get(schema_name='qa')
            logger.info(f"Found 'qa' tenant: {qa_tenant.name} (schema: {qa_tenant.schema_name})")
            
            # Ensure domain with folder='qa' exists
            try:
                domain = Domain.objects.get(folder='qa')
                logger.info(f"Found domain with folder='qa': {domain.domain}, tenant: {domain.tenant.schema_name}")
            except Domain.DoesNotExist:
                logger.info("Creating domain with folder='qa'")
                domain = Domain(
                    domain='localhost',
                    folder='qa',
                    tenant=qa_tenant,
                    is_primary=True
                )
                domain.save()
                logger.info(f"Created domain with folder='qa' for tenant: {qa_tenant.schema_name}")
            
            # Switch to the 'qa' schema
            connection.set_tenant(qa_tenant)
            logger.info(f"Switched to tenant schema: {connection.schema_name}")
            
            # Create a tenant admin user for testing
            email = "ankit@quickassist.co.in"
            
            # Check if the user already exists
            try:
                tenant_user = TenantUser.objects.get(email=email)
                logger.info(f"Found existing TenantUser: {tenant_user.email} (ID: {tenant_user.id})")
            except TenantUser.DoesNotExist:
                # Create a new TenantUser
                tenant_user = TenantUser.objects.create_user(
                    username=email,
                    email=email,
                    password="Password123!",
                    first_name="Ankit",
                    last_name="Admin",
                    is_staff=True
                )
                logger.info(f"Created new TenantUser: {tenant_user.email} (ID: {tenant_user.id})")
            
            # Create or update the UserProfile
            try:
                profile = UserProfile.objects.get(user=tenant_user)
                logger.info(f"Found existing UserProfile for {tenant_user.email} (ID: {profile.id})")
                
                # Ensure the user is a tenant admin
                profile.is_tenant_admin = True
                profile.save()
                logger.info("Updated UserProfile: is_tenant_admin=True")
            except UserProfile.DoesNotExist:
                # Create a new UserProfile
                profile = UserProfile.objects.create(
                    user=tenant_user,
                    is_tenant_admin=True
                )
                logger.info(f"Created new UserProfile for {tenant_user.email}: is_tenant_admin=True")
            
            # Create admin role if it doesn't exist
            admin_role, created = Role.objects.get_or_create(
                name="Admin",
                defaults={"description": "Administrator role with full access"}
            )
            if created:
                logger.info(f"Created new admin role: {admin_role.name}")
            else:
                logger.info(f"Found existing admin role: {admin_role.name}")
            
            # Assign admin role to the user
            user_role, created = UserRole.objects.get_or_create(
                user=tenant_user,
                role=admin_role
            )
            if created:
                logger.info(f"Assigned admin role to user: {tenant_user.email}")
            else:
                logger.info(f"User already has admin role: {tenant_user.email}")
            
            logger.info("Tenant admin user setup completed successfully.")
            
        except Client.DoesNotExist:
            logger.error("'qa' tenant not found")
    
    except Exception as e:
        logger.error(f"Error fixing tenant admin: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())

if __name__ == "__main__":
    fix_tenant_admin()
