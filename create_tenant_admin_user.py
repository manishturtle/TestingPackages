import os
import django
import sys

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'KeyProductSettings.settings')
django.setup()

from django.db import connection
from ecomm_superadmin.models import Client
from django.contrib.auth import get_user_model
from ecomm_tenant.ecomm_tenant_admins.models import UserProfile, Role, UserRole
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_tenant_admin_user():
    """
    Create a tenant admin user in the 'qa' tenant.
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
            logger.info(f"Switched to tenant schema: {connection.schema_name}")
            
            # Get the correct user model for the tenant schema
            User = get_user_model()
            logger.info(f"Using user model: {User.__name__}")
            
            # Check existing users
            users = User.objects.all()
            logger.info(f"Found {users.count()} users in 'qa' schema:")
            for user in users:
                logger.info(f"User: {user.email}, Staff: {getattr(user, 'is_staff', False)}")
            
            # Create a tenant admin user for testing
            email = "ankit@quickassist.co.in"
            
            # Check if the user already exists
            try:
                user = User.objects.get(email=email)
                logger.info(f"User already exists: {user.email}")
            except User.DoesNotExist:
                # Create a new user with the appropriate model
                user = User.objects.create_user(
                    email=email,
                    username=email,  # Set username to email for TenantUser model
                    first_name="Ankit",
                    last_name="Admin",
                    password="Password123!"
                )
                
                # Set is_staff if the model has this field
                if hasattr(user, 'is_staff'):
                    user.is_staff = True
                    user.save()
                
                logger.info(f"Created new user: {user.email}")
            
            # Create or update the user profile
            try:
                profile = UserProfile.objects.get(user=user)
                logger.info(f"User profile already exists for {user.email}")
                
                # Ensure the user is a tenant admin
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
                user=user,
                role=admin_role
            )
            if created:
                logger.info(f"Assigned admin role to user: {user.email}")
            else:
                logger.info(f"User already has admin role: {user.email}")
            
            logger.info("User setup completed successfully.")
            
        except Client.DoesNotExist:
            logger.error("'qa' tenant not found")
    
    except Exception as e:
        logger.error(f"Error creating tenant admin user: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())

if __name__ == "__main__":
    create_tenant_admin_user()
