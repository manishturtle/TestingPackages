import os
import django
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'product.settings')
django.setup()

from django.conf import settings

# Database connection parameters
db_settings = settings.DATABASES['default']
db_name = db_settings['NAME']
db_user = db_settings['USER']
db_password = db_settings['PASSWORD']
db_host = db_settings['HOST']
db_port = db_settings['PORT']

# Connect to PostgreSQL
conn = psycopg2.connect(
    dbname=db_name,
    user=db_user,
    password=db_password,
    host=db_host,
    port=db_port
)
conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
cursor = conn.cursor()

# Create the necessary tables for the accounts app
accounts_tables = """
-- Create the accounts_user table
CREATE TABLE IF NOT EXISTS public.accounts_user (
    id SERIAL PRIMARY KEY,
    password VARCHAR(128) NOT NULL,
    last_login TIMESTAMP WITH TIME ZONE NULL,
    is_superuser BOOLEAN NOT NULL DEFAULT FALSE,
    username VARCHAR(150) NOT NULL UNIQUE,
    first_name VARCHAR(150) NOT NULL DEFAULT '',
    last_name VARCHAR(150) NOT NULL DEFAULT '',
    email VARCHAR(254) NOT NULL UNIQUE,
    is_staff BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    date_joined TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create the accounts_subscriptionplan table
CREATE TABLE IF NOT EXISTS public.accounts_subscriptionplan (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    price DECIMAL(10, 2) NOT NULL,
    max_users INTEGER NOT NULL DEFAULT 5,
    max_storage INTEGER NOT NULL DEFAULT 5,
    features JSONB NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create the accounts_client table
CREATE TABLE IF NOT EXISTS public.accounts_client (
    id SERIAL PRIMARY KEY,
    schema_name VARCHAR(63) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    description TEXT NULL DEFAULT '',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    status VARCHAR(20) NOT NULL DEFAULT 'trial',
    subscription_plan_id INTEGER NULL REFERENCES public.accounts_subscriptionplan(id) ON DELETE SET NULL
);

-- Create the accounts_domain table
CREATE TABLE IF NOT EXISTS public.accounts_domain (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(253) NOT NULL UNIQUE,
    is_primary BOOLEAN NOT NULL DEFAULT TRUE,
    tenant_id INTEGER NOT NULL REFERENCES public.accounts_client(id) ON DELETE CASCADE
);

-- Create the accounts_company table
CREATE TABLE IF NOT EXISTS public.accounts_company (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    industry VARCHAR(100) NULL,
    size VARCHAR(50) NULL,
    country VARCHAR(100) NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    client_id INTEGER NOT NULL REFERENCES public.accounts_client(id) ON DELETE CASCADE
);
"""

# Create the necessary tables for the ecomm_tenant_admins app
ecomm_tenant_admins_tables = """
-- Create the ecomm_tenant_admins_userprofile table
CREATE TABLE IF NOT EXISTS public.ecomm_tenant_admins_userprofile (
    id SERIAL PRIMARY KEY,
    nationality VARCHAR(100) NULL,
    is_company_admin BOOLEAN NOT NULL DEFAULT FALSE,
    is_tenant_admin BOOLEAN NOT NULL DEFAULT FALSE,
    is_email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    otp VARCHAR(6) NULL,
    totp_secret VARCHAR(255) NULL,
    is_2fa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    needs_2fa_setup BOOLEAN NOT NULL DEFAULT FALSE,
    recovery_codes JSONB NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    company_id INTEGER NULL REFERENCES public.accounts_company(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL UNIQUE REFERENCES public.accounts_user(id) ON DELETE CASCADE
);

-- Create the ecomm_tenant_admins_role table
CREATE TABLE IF NOT EXISTS public.ecomm_tenant_admins_role (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create the ecomm_tenant_admins_permission table
CREATE TABLE IF NOT EXISTS public.ecomm_tenant_admins_permission (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    codename VARCHAR(100) NOT NULL UNIQUE,
    description TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create the ecomm_tenant_admins_rolepermission table
CREATE TABLE IF NOT EXISTS public.ecomm_tenant_admins_rolepermission (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    permission_id INTEGER NOT NULL REFERENCES public.ecomm_tenant_admins_permission(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES public.ecomm_tenant_admins_role(id) ON DELETE CASCADE,
    UNIQUE(role_id, permission_id)
);

-- Create the ecomm_tenant_admins_userrole table
CREATE TABLE IF NOT EXISTS public.ecomm_tenant_admins_userrole (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    role_id INTEGER NOT NULL REFERENCES public.ecomm_tenant_admins_role(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES public.accounts_user(id) ON DELETE CASCADE,
    UNIQUE(user_id, role_id)
);

-- Create the ecomm_tenant_admins_pendingregistration table
CREATE TABLE IF NOT EXISTS public.ecomm_tenant_admins_pendingregistration (
    id SERIAL PRIMARY KEY,
    email VARCHAR(254) NOT NULL UNIQUE,
    first_name VARCHAR(150) NOT NULL,
    last_name VARCHAR(150) NOT NULL,
    nationality VARCHAR(100) NULL,
    company_name VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    otp VARCHAR(6) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create the ecomm_tenant_admins_otp table
CREATE TABLE IF NOT EXISTS public.ecomm_tenant_admins_otp (
    id SERIAL PRIMARY KEY,
    otp_code VARCHAR(6) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    user_id INTEGER NOT NULL REFERENCES public.accounts_user(id) ON DELETE CASCADE
);
"""

# Create the Django migration history tables
django_tables = """
-- Create the django_migrations table
CREATE TABLE IF NOT EXISTS public.django_migrations (
    id SERIAL PRIMARY KEY,
    app VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    applied TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Insert migration records
INSERT INTO public.django_migrations (app, name, applied) 
VALUES 
    ('accounts', '0001_initial', NOW()),
    ('ecomm_tenant_admins', '0001_initial', NOW())
ON CONFLICT DO NOTHING;
"""

try:
    # Execute the SQL statements
    print("Creating tables for the accounts app...")
    cursor.execute(accounts_tables)
    
    print("Creating tables for the ecomm_tenant_admins app...")
    cursor.execute(ecomm_tenant_admins_tables)
    
    print("Creating Django migration history tables...")
    cursor.execute(django_tables)
    
    print("Database setup completed successfully!")
    
except Exception as e:
    print(f"Error setting up database: {e}")
    
finally:
    # Close the database connection
    cursor.close()
    conn.close()
