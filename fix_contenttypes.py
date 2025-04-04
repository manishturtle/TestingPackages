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

# Create django_content_type table if it doesn't exist
print("Creating django_content_type table...")
try:
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS django_content_type (
        id serial NOT NULL PRIMARY KEY,
        app_label character varying(100) NOT NULL,
        model character varying(100) NOT NULL,
        CONSTRAINT django_content_type_app_label_model_76bd3d3b_uniq UNIQUE (app_label, model)
    );
    """)
    print("Created django_content_type table")
except Exception as e:
    print(f"Error creating django_content_type table: {e}")

# Create django_admin_log table if it doesn't exist
print("\nCreating django_admin_log table...")
try:
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS django_admin_log (
        id serial NOT NULL PRIMARY KEY,
        action_time timestamp with time zone NOT NULL,
        object_id text,
        object_repr character varying(200) NOT NULL,
        action_flag smallint NOT NULL,
        change_message text NOT NULL,
        content_type_id integer REFERENCES django_content_type(id),
        user_id integer NOT NULL REFERENCES accounts_user(id)
    );
    """)
    print("Created django_admin_log table")
except Exception as e:
    print(f"Error creating django_admin_log table: {e}")

# Create django_session table if it doesn't exist
print("\nCreating django_session table...")
try:
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS django_session (
        session_key character varying(40) NOT NULL PRIMARY KEY,
        session_data text NOT NULL,
        expire_date timestamp with time zone NOT NULL
    );
    """)
    print("Created django_session table")
except Exception as e:
    print(f"Error creating django_session table: {e}")

# Insert content types for core models
print("\nInserting content types for core models...")
content_types = [
    ('admin', 'logentry'),
    ('auth', 'permission'),
    ('auth', 'group'),
    ('contenttypes', 'contenttype'),
    ('sessions', 'session'),
    ('accounts', 'user'),
    ('accounts', 'subscriptionplan'),
    ('accounts', 'client'),
    ('accounts', 'domain'),
    ('accounts', 'company'),
    ('authtoken', 'token'),
    ('authtoken', 'tokenproxy'),
]

for app_label, model in content_types:
    try:
        cursor.execute(
            "INSERT INTO django_content_type (app_label, model) VALUES (%s, %s) ON CONFLICT (app_label, model) DO NOTHING;",
            (app_label, model)
        )
        print(f"Added content type: {app_label}.{model}")
    except Exception as e:
        print(f"Error adding content type {app_label}.{model}: {e}")

# Close the database connection
cursor.close()
conn.close()

print("\nContent type fixes completed. Now run 'python manage.py migrate ecomm_tenant.ecomm_tenant_admins' to apply tenant-specific migrations.")
