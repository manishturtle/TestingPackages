import os
import django
import logging
import jwt
import json
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'KeyProductSettings.settings')
django.setup()

# Import models and settings
from django.conf import settings
from django.db import connection
from ecomm_superadmin.models import Client, User
from ecomm_tenant.ecomm_tenant_admins.models import TenantUser, UserProfile

def create_jwt_token_for_user(email, tenant_slug):
    """Create a JWT token for a user in the specified tenant"""
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
            
            # Create a JWT payload
            now = datetime.utcnow()
            payload = {
                'user_id': user.id,
                'email': user.email,
                'is_staff': user.is_staff,
                'exp': int((now.timestamp() + 3600 * 24)),  # 24 hours expiry
                'iat': int(now.timestamp()),
                'tenant': client.schema_name,
                'tenant_id': client.id
            }
            
            # Try to get user profile info
            try:
                profile = UserProfile.objects.get(user=user)
                payload['is_tenant_admin'] = profile.is_tenant_admin
                payload['is_company_admin'] = profile.is_company_admin
            except UserProfile.DoesNotExist:
                logger.warning("No UserProfile found for user")
            
            # Create a token
            token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
            logger.info(f"Created JWT token: {token[:20]}...")
            logger.info(f"Token payload: {json.dumps(payload, indent=2, default=str)}")
            
            return token
            
        except TenantUser.DoesNotExist:
            logger.error(f"No user found with email {email} in tenant {tenant_slug}")
            return None
            
    except Client.DoesNotExist:
        logger.error(f"No tenant found with slug {tenant_slug}")
        return None
    finally:
        # Reset connection to public schema
        connection.set_schema_to_public()
        logger.info("Reset connection to public schema")

def update_user_permissions(email, tenant_slug):
    """Update user permissions to ensure they have tenant admin access"""
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
            
            # Update user permissions
            user.is_staff = True
            user.save()
            logger.info(f"Updated user is_staff to True")
            
            # Update or create user profile
            profile, created = UserProfile.objects.update_or_create(
                user=user,
                defaults={
                    'is_tenant_admin': True,
                    'is_company_admin': False,
                    'is_email_verified': True
                }
            )
            
            if created:
                logger.info(f"Created new UserProfile with is_tenant_admin=True")
            else:
                logger.info(f"Updated existing UserProfile with is_tenant_admin=True")
                
            return True
            
        except TenantUser.DoesNotExist:
            logger.error(f"No user found with email {email} in tenant {tenant_slug}")
            return False
            
    except Client.DoesNotExist:
        logger.error(f"No tenant found with slug {tenant_slug}")
        return False
    finally:
        # Reset connection to public schema
        connection.set_schema_to_public()
        logger.info("Reset connection to public schema")

if __name__ == "__main__":
    email = "ankit@quickassist.co.in"
    tenant_slug = "qa"
    
    # Update user permissions
    update_user_permissions(email, tenant_slug)
    
    # Create a JWT token
    token = create_jwt_token_for_user(email, tenant_slug)
    if token:
        logger.info(f"Use this token for testing: {token}")
        
        # Print curl command for testing
        logger.info("\nTest with this curl command:")
        logger.info(f'''curl -X GET "http://localhost:8000/api/{tenant_slug}/tenant-admin/users/" \\
-H "Authorization: Bearer {token}" \\
-H "Content-Type: application/json" \\
-H "X-Tenant-Name: {tenant_slug}" \\
-H "X-Tenant-Admin: true"''')
        
        # Print curl command for creating a user
        logger.info("\nCreate a user with this curl command:")
        logger.info(f'''curl -X POST "http://localhost:8000/api/{tenant_slug}/tenant-admin/users/" \\
-H "Authorization: Bearer {token}" \\
-H "Content-Type: application/json" \\
-H "X-Tenant-Name: {tenant_slug}" \\
-H "X-Tenant-Admin: true" \\
-d '{{"email": "test_user3@example.com", "first_name": "Test", "last_name": "User", "user_type": "internal"}}'
''')
