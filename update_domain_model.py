import os
import django
import sys

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'KeyProductSettings.settings')
django.setup()

from django.db import connection

def update_domain_model():
    """
    Update the Domain model to remove the unique constraint from folder field
    and add a unique_together constraint for domain and folder.
    """
    try:
        # Make sure we're in the public schema
        connection.set_schema_to_public()
        
        # Execute SQL to modify the domain table
        with connection.cursor() as cursor:
            # Remove the unique constraint from folder field
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
            
            print("Successfully updated Domain model schema")
            
    except Exception as e:
        print(f"Error updating Domain model: {str(e)}")

if __name__ == "__main__":
    update_domain_model()
