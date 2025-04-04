import os
import django
import sys
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'KeyProductSettings.settings')
django.setup()

from django.db import connection
from ecomm_superadmin.models import Client
from ecomm_tenant.ecomm_tenant_admins.models import TenantUser, UserProfile

def update_tenant_admin_with_correct_password():
    """
    Update the tenant admin user with the correct password and ensure they are properly set up.
    """
    try:
        # Make sure we're in the public schema
        connection.set_schema_to_public()
        logger.info("Starting in public schema")
        
        # Get the 'qa' tenant
        try:
            qa_tenant = Client.objects.get(schema_name='qa')
            logger.info(f"Found 'qa' tenant: {qa_tenant.name} (schema: {qa_tenant.schema_name})")
            
            # Switch to the 'qa' schema
            connection.set_tenant(qa_tenant)
            logger.info(f"Switched to tenant schema: {connection.schema_name}")
            
            # Update the tenant admin user's password
            email = "ankit@quickassist.co.in"
            password = "India@123"
            
            try:
                tenant_user = TenantUser.objects.get(email=email)
                logger.info(f"Found tenant admin user: {tenant_user.email} (ID: {tenant_user.id})")
                
                # Set the password
                tenant_user.set_password(password)
                tenant_user.save()
                logger.info(f"Updated password for tenant admin user: {tenant_user.email}")
                
                # Ensure the user has a profile with tenant admin privileges
                try:
                    profile = UserProfile.objects.get(user=tenant_user)
                    logger.info(f"Found user profile for {tenant_user.email} (ID: {profile.id})")
                    
                    # Ensure the user is a tenant admin
                    if not profile.is_tenant_admin:
                        profile.is_tenant_admin = True
                        profile.save()
                        logger.info(f"Updated user profile: is_tenant_admin=True")
                    else:
                        logger.info(f"User profile already has is_tenant_admin=True")
                except UserProfile.DoesNotExist:
                    # Create a new UserProfile
                    profile = UserProfile.objects.create(
                        user=tenant_user,
                        is_tenant_admin=True
                    )
                    logger.info(f"Created new UserProfile for {tenant_user.email}: is_tenant_admin=True")
                
                return True
            except TenantUser.DoesNotExist:
                logger.error(f"Tenant admin user not found: {email}")
                return False
            
        except Client.DoesNotExist:
            logger.error("'qa' tenant not found")
            return False
    
    except Exception as e:
        logger.error(f"Error updating tenant admin: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return False
    finally:
        # Always reset the schema to public
        connection.set_schema_to_public()
        logger.info("Reset to public schema")

if __name__ == "__main__":
    success = update_tenant_admin_with_correct_password()
    if success:
        logger.info("Successfully updated tenant admin with correct password")
    else:
        logger.error("Failed to update tenant admin")
