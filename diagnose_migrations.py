import os
import sys
import django
from django.conf import settings

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'product.settings')

try:
    django.setup()
    print("Django setup successful")
    
    # Print installed apps
    print("\nINSTALLED_APPS:")
    for app in settings.INSTALLED_APPS:
        print(f"- {app}")
    
    # Print AUTH_USER_MODEL
    print(f"\nAUTH_USER_MODEL: {getattr(settings, 'AUTH_USER_MODEL', 'Not set')}")
    
    # Print TENANT_MODEL
    print(f"\nTENANT_MODEL: {getattr(settings, 'TENANT_MODEL', 'Not set')}")
    
    # Print TENANT_DOMAIN_MODEL
    print(f"\nTENANT_DOMAIN_MODEL: {getattr(settings, 'TENANT_DOMAIN_MODEL', 'Not set')}")
    
    # Try to import models from ecomm_superadmin app
    print("\nTrying to import models from ecomm_superadmin app:")
    try:
        from ecomm_superadmin.models import User, SubscriptionPlan, Client, Domain, Company
        print("Successfully imported models from ecomm_superadmin app")
        # Check model fields
        print(f"User fields: {[f.name for f in User._meta.fields]}")
        print(f"Client fields: {[f.name for f in Client._meta.fields]}")
        print(f"Domain fields: {[f.name for f in Domain._meta.fields]}")
    except Exception as e:
        print(f"Error importing models from ecomm_superadmin app: {e}")
    
    # Try to import models from ecomm_tenant.ecomm_tenant_admins app
    print("\nTrying to import models from ecomm_tenant.ecomm_tenant_admins app:")
    try:
        from ecomm_tenant.ecomm_tenant_admins.models import UserProfile, Role, Permission, RolePermission, UserRole, PendingRegistration, OTP
        print("- UserProfile model imported successfully")
        print("- Role model imported successfully")
        print("- Permission model imported successfully")
        print("- RolePermission model imported successfully")
        print("- UserRole model imported successfully")
        print("- PendingRegistration model imported successfully")
        print("- OTP model imported successfully")
    except ImportError as e:
        print(f"Error importing models from ecomm_tenant.ecomm_tenant_admins app: {e}")
    
except Exception as e:
    print(f"Error during Django setup: {e}")
    import traceback
    traceback.print_exc()
