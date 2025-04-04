"""
Script to create a tenant with all required components:
1. Client entry in ecomm_superadmin_client table
2. Domain entry in ecomm_superadmin_domain table
3. All tenant tables in the tenant schema
4. Tenant admin user in the TenantUser table in the tenant schema
"""
import os
import django
import sys
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'KeyProductSettings.settings')
django.setup()

# Import models after Django setup
from django.db import connection
from django.core.management import call_command
from ecomm_superadmin.models import Client, Domain
from django.contrib.auth.hashers import make_password
from django.utils.crypto import get_random_string
from django.conf import settings

def create_schema_if_not_exists(schema_name):
    """
    Create PostgreSQL schema if it doesn't exist
    """
    try:
        # Connect to PostgreSQL
        conn = psycopg2.connect(
            dbname=settings.DATABASES['default']['NAME'],
            user=settings.DATABASES['default']['USER'],
            password=settings.DATABASES['default']['PASSWORD'],
            host=settings.DATABASES['default']['HOST'],
            port=settings.DATABASES['default']['PORT']
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()
        
        # Check if schema exists
        cursor.execute(f"SELECT schema_name FROM information_schema.schemata WHERE schema_name = '{schema_name}'")
        if not cursor.fetchone():
            # Create schema
            cursor.execute(f"CREATE SCHEMA {schema_name}")
            print(f"Created schema: {schema_name}")
        else:
            print(f"Schema already exists: {schema_name}")
        
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"Error creating schema: {str(e)}")
        return False

def create_tenant(schema_name, name, url_suffix, admin_email, admin_first_name, admin_last_name, admin_password=None):
    """
    Create a tenant with all required components
    
    Args:
        schema_name (str): Schema name for the tenant
        name (str): Display name for the tenant
        url_suffix (str): URL suffix for the tenant
        admin_email (str): Email for the tenant admin
        admin_first_name (str): First name for the tenant admin
        admin_last_name (str): Last name for the tenant admin
        admin_password (str, optional): Password for the tenant admin. If None, a random password will be generated.
    
    Returns:
        tuple: (client, admin_password) - The created client and the admin password
    """
    print(f"Creating tenant: {name} (schema: {schema_name})")
    
    # Step 0: Create the schema in PostgreSQL if it doesn't exist
    if not create_schema_if_not_exists(schema_name):
        print("Failed to create schema, aborting tenant creation")
        return None, None
    
    # Step 1: Create the Client entry
    try:
        # Check if client already exists
        if Client.objects.filter(schema_name=schema_name).exists():
            client = Client.objects.get(schema_name=schema_name)
            print(f"Client already exists: {client.name} (schema: {client.schema_name})")
        else:
            client = Client.objects.create(
                schema_name=schema_name,
                name=name,
                url_suffix=url_suffix,
                paid_until='2030-12-31',  # Set a future date
                on_trial=False
            )
            print(f"Created Client entry: {client.name} (schema: {client.schema_name})")
    except Exception as e:
        print(f"Error creating Client entry: {str(e)}")
        return None, None
    
    # Step 2: Create the Domain entry
    try:
        # Check if domain already exists
        if Domain.objects.filter(tenant=client, domain='localhost').exists():
            domain = Domain.objects.get(tenant=client, domain='localhost')
            print(f"Domain entry already exists with folder: {domain.folder}")
        else:
            domain = Domain.objects.create(
                domain='localhost',  # Default for local development
                tenant=client,
                folder=url_suffix  # Use url_suffix as the folder name
            )
            print(f"Created Domain entry with folder: {domain.folder}")
    except Exception as e:
        print(f"Error creating Domain entry: {str(e)}")
        # Continue anyway, as the tenant was created
    
    # Step 3: Run migrations for the tenant schema to create all required tables
    try:
        # Set connection to tenant schema
        connection.set_tenant(client)
        
        # Run migrations for the tenant schema
        print(f"Running migrations for tenant schema: {client.schema_name}")
        call_command('migrate', schema_name=client.schema_name, interactive=False)
        print(f"Successfully migrated schema '{client.schema_name}'")
        
        # Step 4: Create the tenant admin user
        if not admin_password:
            # Generate a secure random password
            admin_password = get_random_string(length=12)
        
        # Import the tenant-specific models
        from ecomm_tenant.ecomm_tenant_admins.models import TenantUser, UserProfile, Role, UserRole
        
        # Check if tenant admin already exists
        if TenantUser.objects.filter(email=admin_email).exists():
            admin_user = TenantUser.objects.get(email=admin_email)
            print(f"Tenant admin user already exists: {admin_user.email}")
            
            # Ensure the user has is_staff=True
            if not admin_user.is_staff:
                admin_user.is_staff = True
                admin_user.save()
                print(f"Updated tenant admin user with is_staff=True")
        else:
            # Create the tenant admin user
            admin_user = TenantUser.objects.create_user(
                username=admin_email,
                email=admin_email,
                password=admin_password,
                first_name=admin_first_name,
                last_name=admin_last_name,
                is_staff=True,  # This makes them a tenant admin
                is_active=True
            )
            print(f"Created tenant admin user: {admin_email} in tenant: {client.schema_name}")
        
        # Check if user profile exists
        if hasattr(admin_user, 'profile'):
            user_profile = admin_user.profile
            # Ensure the profile has is_tenant_admin=True
            if not user_profile.is_tenant_admin:
                user_profile.is_tenant_admin = True
                user_profile.is_company_admin = True
                user_profile.is_email_verified = True
                user_profile.save()
                print(f"Updated user profile with is_tenant_admin=True")
        else:
            # Create a UserProfile for the admin user
            user_profile = UserProfile.objects.create(
                user=admin_user,
                is_tenant_admin=True,
                is_company_admin=True,
                is_email_verified=True  # Auto-verify the tenant admin
            )
            print(f"Created user profile with is_tenant_admin=True")
        
        # Create tenant admin role if it doesn't exist
        admin_role, created = Role.objects.get_or_create(
            name='tenant_admin',
            defaults={
                'description': 'Tenant administrator with full access to tenant resources'
            }
        )
        
        # Check if user role exists
        if not UserRole.objects.filter(user=admin_user, role=admin_role).exists():
            # Assign the admin role to the user
            UserRole.objects.create(
                user=admin_user,
                role=admin_role
            )
            print(f"Assigned tenant admin role to user")
        
        # Verify that the user was created correctly
        verification_user = TenantUser.objects.get(email=admin_email)
        print(f"Verification - User exists: {verification_user is not None}")
        print(f"Verification - User is_staff: {verification_user.is_staff}")
        
        print(f"Tenant admin credentials - Email: {admin_email}, Password: {admin_password if admin_password else 'Using existing password'}")
        
        return client, admin_password
    
    except Exception as e:
        print(f"Error setting up tenant: {str(e)}")
        import traceback
        traceback.print_exc()
        return client, None
    
    finally:
        # Reset to public schema
        connection.set_schema_to_public()

def main():
    """
    Main function to create tenants based on command line arguments
    """
    if len(sys.argv) < 5:
        print("Usage: python setup_tenant.py <schema_name> <name> <url_suffix> <admin_email> [admin_first_name] [admin_last_name] [admin_password]")
        return
    
    schema_name = sys.argv[1]
    name = sys.argv[2]
    url_suffix = sys.argv[3]
    admin_email = sys.argv[4]
    admin_first_name = sys.argv[5] if len(sys.argv) > 5 else "Admin"
    admin_last_name = sys.argv[6] if len(sys.argv) > 6 else "User"
    admin_password = sys.argv[7] if len(sys.argv) > 7 else None
    
    client, password = create_tenant(
        schema_name=schema_name,
        name=name,
        url_suffix=url_suffix,
        admin_email=admin_email,
        admin_first_name=admin_first_name,
        admin_last_name=admin_last_name,
        admin_password=admin_password
    )
    
    if client:
        print(f"Successfully created tenant: {client.name}")
        print(f"Tenant admin credentials - Email: {admin_email}, Password: {password if password else 'Using existing password'}")
    else:
        print("Failed to create tenant")

if __name__ == "__main__":
    main()
