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

# Create auth_permission table if it doesn't exist
print("Creating auth_permission table...")
try:
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS auth_permission (
        id serial NOT NULL PRIMARY KEY,
        name character varying(255) NOT NULL,
        content_type_id integer NOT NULL REFERENCES django_content_type(id),
        codename character varying(100) NOT NULL,
        CONSTRAINT auth_permission_content_type_id_codename_01ab375a_uniq UNIQUE (content_type_id, codename)
    );
    """)
    print("Created auth_permission table")
except Exception as e:
    print(f"Error creating auth_permission table: {e}")

# Create auth_group table if it doesn't exist
print("\nCreating auth_group table...")
try:
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS auth_group (
        id serial NOT NULL PRIMARY KEY,
        name character varying(150) NOT NULL UNIQUE
    );
    """)
    print("Created auth_group table")
except Exception as e:
    print(f"Error creating auth_group table: {e}")

# Create auth_group_permissions table if it doesn't exist
print("\nCreating auth_group_permissions table...")
try:
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS auth_group_permissions (
        id serial NOT NULL PRIMARY KEY,
        group_id integer NOT NULL REFERENCES auth_group(id),
        permission_id integer NOT NULL REFERENCES auth_permission(id),
        CONSTRAINT auth_group_permissions_group_id_permission_id_0cd325b0_uniq UNIQUE (group_id, permission_id)
    );
    """)
    print("Created auth_group_permissions table")
except Exception as e:
    print(f"Error creating auth_group_permissions table: {e}")

# Create auth_user_groups table if it doesn't exist
print("\nCreating auth_user_groups table...")
try:
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS auth_user_groups (
        id serial NOT NULL PRIMARY KEY,
        user_id integer NOT NULL REFERENCES accounts_user(id),
        group_id integer NOT NULL REFERENCES auth_group(id),
        CONSTRAINT auth_user_groups_user_id_group_id_94350c0c_uniq UNIQUE (user_id, group_id)
    );
    """)
    print("Created auth_user_groups table")
except Exception as e:
    print(f"Error creating auth_user_groups table: {e}")

# Create auth_user_user_permissions table if it doesn't exist
print("\nCreating auth_user_user_permissions table...")
try:
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS auth_user_user_permissions (
        id serial NOT NULL PRIMARY KEY,
        user_id integer NOT NULL REFERENCES accounts_user(id),
        permission_id integer NOT NULL REFERENCES auth_permission(id),
        CONSTRAINT auth_user_user_permissions_user_id_permission_id_14a6b632_uniq UNIQUE (user_id, permission_id)
    );
    """)
    print("Created auth_user_user_permissions table")
except Exception as e:
    print(f"Error creating auth_user_user_permissions table: {e}")

# Close the database connection
cursor.close()
conn.close()

print("\nAuth tables created successfully. Now run 'python manage.py migrate ecomm_tenant.ecomm_tenant_admins' to apply tenant-specific migrations.")
