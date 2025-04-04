import os
import django
import sys

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'KeyProductSettings.settings')
django.setup()

from django.db import connection

def fix_domain_constraints():
    """
    Fix the Domain model constraints to properly support multiple tenants sharing the same domain
    with different folders.
    """
    try:
        # Make sure we're in the public schema
        connection.set_schema_to_public()
        
        # Execute SQL to modify the domain table
        with connection.cursor() as cursor:
            # First, drop the unique constraint on the domain field
            cursor.execute("""
            ALTER TABLE ecomm_superadmin_domain 
            DROP CONSTRAINT IF EXISTS ecomm_superadmin_domain_domain_key;
            """)
            
            # Remove the unique constraint from folder field if it exists
            cursor.execute("""
            ALTER TABLE ecomm_superadmin_domain 
            DROP CONSTRAINT IF EXISTS ecomm_superadmin_domain_folder_key;
            """)
            
            # Add unique constraint for domain and folder
            cursor.execute("""
            ALTER TABLE ecomm_superadmin_domain 
            DROP CONSTRAINT IF EXISTS ecomm_superadmin_domain_domain_folder_uniq;
            """)
            
            cursor.execute("""
            ALTER TABLE ecomm_superadmin_domain 
            ADD CONSTRAINT ecomm_superadmin_domain_domain_folder_uniq 
            UNIQUE (domain, folder);
            """)
            
            print("Successfully fixed Domain model constraints")
            
    except Exception as e:
        print(f"Error fixing Domain model constraints: {str(e)}")

if __name__ == "__main__":
    fix_domain_constraints()
