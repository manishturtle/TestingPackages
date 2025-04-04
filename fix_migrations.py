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

# Reset all migrations
print("Resetting all migrations...")
try:
    cursor.execute("DELETE FROM django_migrations;")
    print("Deleted all migrations from django_migrations")
except Exception as e:
    print(f"Error deleting migrations: {e}")

# Add initial migrations for auth and contenttypes
print("\nAdding initial migrations for core apps...")
migrations_to_add = [
    ("auth", "0001_initial"),
    ("auth", "0002_alter_permission_name_max_length"),
    ("auth", "0003_alter_user_email_max_length"),
    ("auth", "0004_alter_user_username_opts"),
    ("auth", "0005_alter_user_last_login_null"),
    ("auth", "0006_require_contenttypes_0002"),
    ("auth", "0007_alter_validators_add_error_messages"),
    ("auth", "0008_alter_user_username_max_length"),
    ("auth", "0009_alter_user_last_name_max_length"),
    ("auth", "0010_alter_group_name_max_length"),
    ("auth", "0011_update_proxy_permissions"),
    ("auth", "0012_alter_user_first_name_max_length"),
    ("contenttypes", "0001_initial"),
    ("contenttypes", "0002_remove_content_type_name"),
    ("admin", "0001_initial"),
    ("admin", "0002_logentry_remove_auto_add"),
    ("admin", "0003_logentry_add_action_flag_choices"),
    ("sessions", "0001_initial"),
]

for app, name in migrations_to_add:
    try:
        cursor.execute(
            "INSERT INTO django_migrations (app, name, applied) VALUES (%s, %s, NOW());",
            (app, name)
        )
        print(f"Added migration: {app}.{name}")
    except Exception as e:
        print(f"Error adding migration {app}.{name}: {e}")

# Add accounts migrations
print("\nAdding accounts migrations...")
try:
    cursor.execute(
        "INSERT INTO django_migrations (app, name, applied) VALUES (%s, %s, NOW());",
        ("ecomm_superadmin", "0001_initial")
    )
    print("Added migration: ecomm_superadmin.0001_initial")
except Exception as e:
    print(f"Error adding ecomm_superadmin migration: {e}")

# Close the database connection
cursor.close()
conn.close()

print("\nMigration fixes completed. Now run 'python manage.py migrate_schemas --tenant' to apply tenant-specific migrations.")
