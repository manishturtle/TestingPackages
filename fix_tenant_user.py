import os
import django
import sys

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'KeyProductSettings.settings')
django.setup()

from django.db import connection
from ecomm_superadmin.models import Client, User
from ecomm_tenant.ecomm_tenant_admins.models import UserProfile, TenantUser
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def fix_tenant_user():
    """
    Fix the user model issue in the 'qa' tenant.
    """
    try:
        # Make sure we're in the public schema
        connection.set_schema_to_public()
        
        # Get the 'qa' tenant
        try:
            qa_tenant = Client.objects.get(schema_name='qa')
            logger.info(f"Found 'qa' tenant: {qa_tenant.name} (schema: {qa_tenant.schema_name})")
            
            # Switch to the 'qa' schema
            connection.set_tenant(qa_tenant)
            
            # Check existing users
            users = User.objects.all()
            logger.info(f"Found {users.count()} users in 'qa' schema:")
            for user in users:
                logger.info(f"User: {user.email}, Staff: {user.is_staff}")
            
            # Create a tenant admin user for testing
            email = "ankit@quickassist.co.in"
            
            # Check if the user already exists
            try:
                user = User.objects.get(email=email)
                logger.info(f"User already exists: {user.email}")
            except User.DoesNotExist:
                # Create a new user
                user = User.objects.create(
                    email=email,
                    first_name="Ankit",
                    last_name="Admin",
                    is_staff=True
                )
                user.set_password("Password123!")
                user.save()
                logger.info(f"Created new user: {user.email}")
            
            # Create or update the user profile
            try:
                profile = UserProfile.objects.get(user=user)
                logger.info(f"User profile already exists for {user.email}")
                
                # Ensure the user is a tenant admin
                if not profile.is_tenant_admin:
                    profile.is_tenant_admin = True
                    profile.save()
                    logger.info(f"Updated user profile: is_tenant_admin=True")
            except UserProfile.DoesNotExist:
                # Create a new profile
                profile = UserProfile.objects.create(
                    user=user,
                    is_tenant_admin=True
                )
                logger.info(f"Created new user profile for {user.email}: is_tenant_admin=True")
            
            logger.info("User setup completed successfully.")
            
        except Client.DoesNotExist:
            logger.error("'qa' tenant not found")
    
    except Exception as e:
        logger.error(f"Error fixing tenant user: {str(e)}")

if __name__ == "__main__":
    fix_tenant_user()
