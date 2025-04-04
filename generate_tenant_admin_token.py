import os
import django
import logging
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
from ecomm_superadmin.models import Client
from ecomm_tenant.ecomm_tenant_admins.models import TenantUser, UserProfile
from rest_framework_simplejwt.tokens import RefreshToken

def generate_admin_token(email, tenant_slug):
    """Generate a valid JWT token for a tenant admin user"""
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
            
            # Ensure user is a tenant admin
            user.is_staff = True
            user.save(update_fields=['is_staff'])
            logger.info(f"Ensured user has is_staff=True")
            
            # Get or create user profile with is_tenant_admin=True
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
            
            # Generate JWT token with all required claims
            refresh = RefreshToken.for_user(user)
            
            # Add custom claims to the token
            refresh['is_tenant_admin'] = True
            refresh['is_staff'] = True
            refresh['tenant_id'] = client.id
            refresh['tenant_schema'] = client.schema_name
            refresh['tenant_slug'] = client.url_suffix
            
            # Get token strings
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)
            
            # Create token JSON
            token_json = {
                'access': access_token,
                'refresh': refresh_token
            }
            
            # Save to file
            with open('tenant_admin_token.json', 'w') as f:
                json.dump(token_json, f, indent=2)
            
            logger.info(f"Token saved to tenant_admin_token.json")
            
            # Print instructions
            print("\n=== INSTRUCTIONS ===")
            print("1. Open your browser's developer console (F12)")
            print("2. Run this command to update your token:")
            print(f"   localStorage.setItem('token', JSON.stringify({json.dumps(token_json)}))")
            print("3. Refresh the page and try again")
            
            return token_json
            
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

if __name__ == "__main__":
    email = input("Enter the tenant admin email: ")
    tenant_slug = input("Enter the tenant slug: ")
    
    generate_admin_token(email, tenant_slug)
