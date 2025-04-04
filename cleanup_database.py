import os
import django
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'erp_project.settings')
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

# Define tables to drop
tables_to_drop = [
    "accounts_user",
    "accounts_company",
    "accounts_client",
    "accounts_domain",
    "accounts_subscriptionplan",
    "accounts_subscription",
    "ecomm_tenant_admins_userprofile",
    "ecomm_tenant_admins_role",
    "ecomm_tenant_admins_permission",
    "ecomm_tenant_admins_rolepermission",
    "ecomm_tenant_admins_userrole",
    "ecomm_tenant_admins_pendingregistration",
    "ecomm_tenant_admins_otp",
    # Add any other tables you want to drop
]

print("Removing tenant-specific tables from public schema...")
for table in tables_to_drop:
    try:
        cursor.execute(f"DROP TABLE IF EXISTS public.{table} CASCADE;")
        print(f"Dropped table: {table}")
    except Exception as e:
        print(f"Error dropping table {table}: {e}")

# Reset Django migrations
print("\nResetting Django migrations...")
try:
    cursor.execute("DELETE FROM django_migrations WHERE app IN ('ecomm_tenant.ecomm_tenant_admins');")
    print("Deleted ecomm_tenant.ecomm_tenant_admins migrations from django_migrations")
except Exception as e:
    print(f"Error deleting migrations: {e}")

# Create public schema if it doesn't exist
try:
    cursor.execute("CREATE SCHEMA IF NOT EXISTS public;")
    print("Created or confirmed public schema")
except Exception as e:
    print(f"Error creating public schema: {e}")

# Close the database connection
cursor.close()
conn.close()

print("\nDatabase cleanup completed. Now run migrations to properly set up the schemas.")
