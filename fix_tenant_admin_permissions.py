import os
import django
import logging
import jwt
import json
from datetime import datetime, timedelta

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
from rest_framework_simplejwt.tokens import RefreshToken

def fix_tenant_admin_permissions(email, tenant_slug):
    """Fix tenant admin permissions and create a valid JWT token"""
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
            user.save(update_fields=['is_staff'])
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
            
            # Create a new JWT token with proper claims
            refresh = RefreshToken.for_user(user)
            
            # Add custom claims to the token
            refresh['is_tenant_admin'] = True
            refresh['is_staff'] = True
            refresh['tenant_id'] = client.id
            refresh['tenant_schema'] = client.schema_name
            refresh['tenant_slug'] = client.url_suffix
            
            # Convert token to string
            token_str = str(refresh.access_token)
            refresh_str = str(refresh)
            
            # Print the token details
            logger.info(f"Created JWT access token: {token_str[:20]}...")
            logger.info(f"Created JWT refresh token: {refresh_str[:20]}...")
            
            # Write tokens to a file for easy access
            token_data = {
                "access": token_str,
                "refresh": refresh_str
            }
            
            with open('tenant_admin_token.json', 'w') as f:
                json.dump(token_data, f, indent=2)
            logger.info("Tokens saved to tenant_admin_token.json")
            
            # Decode the token to verify claims
            decoded = jwt.decode(token_str, options={"verify_signature": False})
            logger.info(f"Token claims: {json.dumps(decoded, indent=2)}")
            
            # Print instructions for using the token
            logger.info("\n=== INSTRUCTIONS FOR FIXING THE ISSUE ===")
            logger.info("1. Copy the following token data:")
            logger.info(json.dumps({
                "access": token_str,
                "refresh": refresh_str
            }, indent=2))
            logger.info("\n2. In your browser, open the developer console (F12)")
            logger.info("3. Run this command to update your token:")
            logger.info(f"   localStorage.setItem('token', JSON.stringify({{\n      \"access\": \"{token_str}\",\n      \"refresh\": \"{refresh_str}\"\n    }}))")
            logger.info("4. Refresh the page and try creating a tenant user again")
            
            # Print curl command for testing
            logger.info("\nTest with this curl command:")
            logger.info(f'''curl -X GET "http://localhost:8000/api/{tenant_slug}/tenant-admin/users/" \\
-H "Authorization: Bearer {token_str}" \\
-H "Content-Type: application/json" \\
-H "X-Tenant-Name: {tenant_slug}" \\
-H "X-Tenant-Admin: true"''')
            
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
    
    # Fix tenant admin permissions and create a valid JWT token
    fix_tenant_admin_permissions(email, tenant_slug)
