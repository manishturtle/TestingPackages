"""
Simple script to create a tenant with exactly what's needed:
1. Client entry in ecomm_superadmin_client table
2. Domain entry in ecomm_superadmin_domain table
3. Tenant admin user in the TenantUser table in the tenant schema
"""
import os
import django
import sys

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'KeyProductSettings.settings')
django.setup()

# Import models after Django setup
from django.db import connection
from django.core.management import call_command
from ecomm_superadmin.models import Client, Domain
from django.contrib.auth.hashers import make_password

def create_tenant(schema_name, name, url_suffix, admin_email, admin_password):
    """
    Create a tenant with the required components
    """
    print(f"Creating tenant: {name} (schema: {schema_name})")
    
    # Step 1: Create the Client entry
    client = Client.objects.create(
        schema_name=schema_name,
        name=name,
        url_suffix=url_suffix,
        paid_until='2030-12-31',
        on_trial=False
    )
    print(f"Created Client entry: {client.name} (schema: {client.schema_name})")
    
    # Step 2: Create the Domain entry
    domain = Domain.objects.create(
        domain='localhost',
        tenant=client,
        folder=url_suffix
    )
    print(f"Created Domain entry with folder: {domain.folder}")
    
    # Step 3: Run migrations for the tenant schema
    connection.set_tenant(client)
    
    # Create the tenant admin user directly with SQL
    cursor = connection.cursor()
    
    # First, create the tenant_user table if it doesn't exist
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ecomm_tenant_admins_tenantuser (
        id SERIAL PRIMARY KEY,
        password VARCHAR(128) NOT NULL,
        last_login TIMESTAMP NULL,
        is_superuser BOOLEAN NOT NULL,
        username VARCHAR(150) NOT NULL UNIQUE,
        email VARCHAR(254) NOT NULL UNIQUE,
        first_name VARCHAR(150) NOT NULL,
        last_name VARCHAR(150) NOT NULL,
        is_active BOOLEAN NOT NULL,
        is_staff BOOLEAN NOT NULL,
        date_joined TIMESTAMP NOT NULL
    )
    """)
    
    # Create the tenant admin user
    hashed_password = make_password(admin_password)
    cursor.execute("""
    INSERT INTO ecomm_tenant_admins_tenantuser 
    (password, last_login, is_superuser, username, email, first_name, last_name, is_active, is_staff, date_joined)
    VALUES (%s, NULL, FALSE, %s, %s, 'Admin', 'User', TRUE, TRUE, NOW())
    """, [hashed_password, admin_email, admin_email])
    
    print(f"Created tenant admin user: {admin_email} in tenant: {client.schema_name}")
    
    # Reset to public schema
    connection.set_schema_to_public()
    
    return client

if __name__ == "__main__":
    if len(sys.argv) < 6:
        print("Usage: python create_tenant_simple.py <schema_name> <name> <url_suffix> <admin_email> <admin_password>")
        sys.exit(1)
    
    schema_name = sys.argv[1]
    name = sys.argv[2]
    url_suffix = sys.argv[3]
    admin_email = sys.argv[4]
    admin_password = sys.argv[5]
    
    client = create_tenant(
        schema_name=schema_name,
        name=name,
        url_suffix=url_suffix,
        admin_email=admin_email,
        admin_password=admin_password
    )
    
    print(f"Successfully created tenant: {client.name}")
    print(f"Tenant admin credentials - Email: {admin_email}, Password: {admin_password}")
