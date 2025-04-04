"""
Script to ensure proper tenant setup with exactly what's required:
1. Client entry in ecomm_superadmin_client table
2. Domain entry in ecomm_superadmin_domain table
3. Tenant admin user in the TenantUser table in the tenant schema
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
from django.conf import settings
from ecomm_superadmin.models import Client, Domain
from django.contrib.auth.hashers import make_password

def ensure_schema_exists(schema_name):
    """Ensure the PostgreSQL schema exists"""
    db_settings = settings.DATABASES['default']
    conn = psycopg2.connect(
        dbname=db_settings['NAME'],
        user=db_settings['USER'],
        password=db_settings['PASSWORD'],
        host=db_settings['HOST'],
        port=db_settings['PORT']
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

def ensure_client_exists(schema_name, name, url_suffix):
    """Ensure Client entry exists in ecomm_superadmin_client table"""
    try:
        client, created = Client.objects.get_or_create(
            schema_name=schema_name,
            defaults={
                'name': name,
                'url_suffix': url_suffix,
                'paid_until': '2030-12-31',
                'on_trial': False
            }
        )
        if created:
            print(f"Created Client entry: {client.name} (schema: {client.schema_name})")
        else:
            print(f"Client already exists: {client.name} (schema: {client.schema_name})")
        return client
    except Exception as e:
        print(f"Error with Client entry: {str(e)}")
        return None

def ensure_domain_exists(client, folder):
    """Ensure Domain entry exists in ecomm_superadmin_domain table"""
    try:
        domain, created = Domain.objects.get_or_create(
            tenant=client,
            domain='localhost',
            defaults={'folder': folder}
        )
        if created:
            print(f"Created Domain entry with folder: {domain.folder}")
        else:
            print(f"Domain already exists with folder: {domain.folder}")
        return domain
    except Exception as e:
        print(f"Error with Domain entry: {str(e)}")
        return None

def ensure_tenant_admin_exists(schema_name, admin_email, admin_password):
    """Ensure tenant admin user exists in TenantUser table in tenant schema"""
    # Connect directly to the tenant schema
    db_settings = settings.DATABASES['default']
    conn = psycopg2.connect(
        dbname=db_settings['NAME'],
        user=db_settings['USER'],
        password=db_settings['PASSWORD'],
        host=db_settings['HOST'],
        port=db_settings['PORT']
    )
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cursor = conn.cursor()
    
    # Set search path to tenant schema
    cursor.execute(f"SET search_path TO {schema_name}")
    
    # Check if TenantUser table exists
    cursor.execute("""
    SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_schema = %s
        AND table_name = 'ecomm_tenant_admins_tenantuser'
    )
    """, [schema_name])
    
    table_exists = cursor.fetchone()[0]
    
    if not table_exists:
        # Create TenantUser table
        print(f"Creating TenantUser table in schema: {schema_name}")
        cursor.execute(f"""
        CREATE TABLE {schema_name}.ecomm_tenant_admins_tenantuser (
            id SERIAL PRIMARY KEY,
            password VARCHAR(128) NOT NULL,
            last_login TIMESTAMP WITH TIME ZONE NULL,
            is_superuser BOOLEAN NOT NULL DEFAULT FALSE,
            username VARCHAR(150) NOT NULL UNIQUE,
            email VARCHAR(254) NOT NULL UNIQUE,
            first_name VARCHAR(150) NOT NULL,
            last_name VARCHAR(150) NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            is_staff BOOLEAN NOT NULL DEFAULT FALSE,
            date_joined TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
        )
        """)
    
    # Check if admin user exists
    cursor.execute(f"""
    SELECT id FROM {schema_name}.ecomm_tenant_admins_tenantuser 
    WHERE email = %s
    """, [admin_email])
    
    user_exists = cursor.fetchone()
    
    if user_exists:
        # Update existing user to ensure is_staff=True
        print(f"Tenant admin user already exists: {admin_email}")
        cursor.execute(f"""
        UPDATE {schema_name}.ecomm_tenant_admins_tenantuser 
        SET is_staff = TRUE 
        WHERE email = %s
        """, [admin_email])
        print(f"Updated tenant admin user with is_staff=True")
    else:
        # Create tenant admin user
        hashed_password = make_password(admin_password)
        cursor.execute(f"""
        INSERT INTO {schema_name}.ecomm_tenant_admins_tenantuser 
        (password, is_superuser, username, email, first_name, last_name, is_active, is_staff, date_joined)
        VALUES (%s, FALSE, %s, %s, 'Admin', 'User', TRUE, TRUE, NOW())
        """, [hashed_password, admin_email, admin_email])
        print(f"Created tenant admin user: {admin_email} in tenant: {schema_name}")
    
    cursor.close()
    conn.close()

def fix_tenant_setup(schema_name, name, url_suffix, admin_email, admin_password):
    """Fix tenant setup to ensure all three requirements are met"""
    print(f"Fixing tenant setup for: {name} (schema: {schema_name})")
    
    # Step 1: Ensure schema exists
    ensure_schema_exists(schema_name)
    
    # Step 2: Ensure Client entry exists
    client = ensure_client_exists(schema_name, name, url_suffix)
    if not client:
        return False
    
    # Step 3: Ensure Domain entry exists
    domain = ensure_domain_exists(client, url_suffix)
    if not domain:
        return False
    
    # Step 4: Ensure tenant admin user exists
    ensure_tenant_admin_exists(schema_name, admin_email, admin_password)
    
    print(f"Tenant setup fixed for: {name} (schema: {schema_name})")
    print(f"Tenant admin credentials - Email: {admin_email}, Password: {admin_password}")
    return True

if __name__ == "__main__":
    if len(sys.argv) < 6:
        print("Usage: python fix_tenant_setup.py <schema_name> <name> <url_suffix> <admin_email> <admin_password>")
        sys.exit(1)
    
    schema_name = sys.argv[1]
    name = sys.argv[2]
    url_suffix = sys.argv[3]
    admin_email = sys.argv[4]
    admin_password = sys.argv[5]
    
    success = fix_tenant_setup(
        schema_name=schema_name,
        name=name,
        url_suffix=url_suffix,
        admin_email=admin_email,
        admin_password=admin_password
    )
    
    if success:
        print("Tenant setup fixed successfully!")
    else:
        print("Failed to fix tenant setup")
