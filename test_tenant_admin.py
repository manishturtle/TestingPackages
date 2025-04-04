"""
Test script to check tenant admin permissions
"""
import os
import django
import logging
import sys

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'KeyProductSettings.settings')
django.setup()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import models after Django setup
from django.db import connection
from ecomm_superadmin.models import Client, Domain
from ecomm_tenant.ecomm_tenant_admins.models import TenantUser
from django.contrib.auth import authenticate

def test_tenant_admin_permissions(tenant_slug, email, password):
    """
    Test if a user has tenant admin permissions in a specific tenant
    """
    logger.info(f"Testing tenant admin permissions for {email} in tenant {tenant_slug}")
    
    # Step 1: Find the tenant
    try:
        # Try by domain folder first
        try:
            domain = Domain.objects.get(folder=tenant_slug)
            client = domain.tenant
            logger.info(f"Found tenant via domain folder: {tenant_slug}, tenant: {client.schema_name}")
        except Domain.DoesNotExist:
            # If not found by folder, try the url_suffix
            client = Client.objects.get(url_suffix=tenant_slug)
            logger.info(f"Found tenant via url_suffix: {tenant_slug}, tenant: {client.schema_name}")
        
        # Step 2: Set the tenant schema
        connection.set_tenant(client)
        logger.info(f"Set connection schema to: {connection.schema_name}")
        
        # Step 3: Check if the user exists in this tenant
        try:
            user = TenantUser.objects.get(email=email)
            logger.info(f"Found user in tenant: {user.email}, is_staff: {user.is_staff}")
            
            # Step 4: Check if the user is a tenant admin (is_staff=True)
            if user.is_staff:
                logger.info(f"User {email} is a tenant admin in {tenant_slug}")
            else:
                logger.info(f"User {email} is NOT a tenant admin in {tenant_slug} (is_staff=False)")
                
            # Step 5: Try to authenticate the user
            auth_user = authenticate(username=email, password=password)
            if auth_user:
                logger.info(f"Authentication successful for {email}")
                logger.info(f"Authenticated user is_staff: {auth_user.is_staff}")
                logger.info(f"Authenticated user type: {type(auth_user).__name__}")
            else:
                logger.info(f"Authentication failed for {email}")
                
            return user.is_staff
            
        except TenantUser.DoesNotExist:
            logger.error(f"User {email} not found in tenant {tenant_slug}")
            return False
            
    except (Domain.DoesNotExist, Client.DoesNotExist) as e:
        logger.error(f"Tenant {tenant_slug} not found: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Error testing tenant admin permissions: {str(e)}")
        return False

if __name__ == "__main__":
    # Get tenant slug and credentials from command line arguments or use defaults
    tenant_slug = sys.argv[1] if len(sys.argv) > 1 else "qa"
    email = sys.argv[2] if len(sys.argv) > 2 else "ankit@quickassist.co.in"
    password = sys.argv[3] if len(sys.argv) > 3 else "India@123"
    
    # Test tenant admin permissions
    is_tenant_admin = test_tenant_admin_permissions(tenant_slug, email, password)
    
    if is_tenant_admin:
        logger.info(f"✅ {email} is confirmed as a tenant admin in {tenant_slug}")
    else:
        logger.info(f"❌ {email} is NOT a tenant admin in {tenant_slug}")
