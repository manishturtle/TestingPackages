import os
import django
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'KeyProductSettings.settings')
django.setup()

# Import models
from django.db import connection
from ecomm_superadmin.models import Client
from ecomm_tenant.ecomm_tenant_admins.models import TenantUser, UserProfile

def check_tenant_admin_status(email, tenant_slug):
    """Check if a user is a tenant admin in the specified tenant"""
    try:
        # Find the tenant
        client = Client.objects.get(url_suffix=tenant_slug)
        logger.info(f"Found tenant: {client.name} (schema: {client.schema_name})")
        
        # Switch to tenant schema
        connection.set_tenant(client)
        logger.info(f"Switched to schema: {connection.schema_name}")
        
        # Find the user
        try:
            user = TenantUser.objects.get(email=email)
            logger.info(f"Found user: {user.email} (ID: {user.id})")
            logger.info(f"User is_staff: {user.is_staff}")
            logger.info(f"User is_superuser: {user.is_superuser}")
            logger.info(f"User is_active: {user.is_active}")
            
            # Check user profile
            try:
                profile = UserProfile.objects.get(user=user)
                logger.info(f"Found user profile (ID: {profile.id})")
                logger.info(f"Profile is_tenant_admin: {profile.is_tenant_admin}")
                logger.info(f"Profile is_company_admin: {profile.is_company_admin}")
                
                # If not a tenant admin, update the profile
                if not profile.is_tenant_admin:
                    logger.info("User is not a tenant admin. Updating profile...")
                    profile.is_tenant_admin = True
                    profile.save()
                    logger.info("Profile updated. User is now a tenant admin.")
                
            except UserProfile.DoesNotExist:
                logger.error(f"No UserProfile found for user {email}")
                
                # Create a profile for the user
                logger.info("Creating UserProfile for the user...")
                profile = UserProfile.objects.create(
                    user=user,
                    is_tenant_admin=True,
                    is_company_admin=False,
                    is_email_verified=True,
                    is_2fa_enabled=False,
                    needs_2fa_setup=False
                )
                logger.info(f"Created UserProfile (ID: {profile.id}) with is_tenant_admin=True")
                
        except TenantUser.DoesNotExist:
            logger.error(f"No user found with email {email} in tenant {tenant_slug}")
            
    except Client.DoesNotExist:
        logger.error(f"No tenant found with slug {tenant_slug}")
    finally:
        # Reset connection to public schema
        connection.set_schema_to_public()
        logger.info("Reset connection to public schema")

if __name__ == "__main__":
    # Check and update tenant admin status
    check_tenant_admin_status("ankit@quickassist.co.in", "qa")
