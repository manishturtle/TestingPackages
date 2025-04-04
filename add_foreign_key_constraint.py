"""
Script to add the foreign key constraint between company and CRM client tables
"""
import os
import psycopg2
from django.conf import settings
import django

# Initialize Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'KeyProductSettings.settings')
django.setup()

# Get database connection parameters from Django settings
db_settings = settings.DATABASES['default']

# Connect to the database
conn = psycopg2.connect(
    dbname=db_settings['NAME'],
    user=db_settings['USER'],
    password=db_settings['PASSWORD'],
    host=db_settings['HOST'],
    port=db_settings['PORT']
)

try:
    # Make the connection autocommit
    conn.autocommit = True
    
    # Create a cursor
    cursor = conn.cursor()
    
    # Switch to the 'qa' schema
    cursor.execute("SET search_path TO qa;")
    
    # Now add the foreign key constraint
    print("Adding foreign key constraint...")
    cursor.execute("""
        DO $$
        BEGIN
            -- Check if the foreign key constraint already exists
            IF NOT EXISTS (
                SELECT 1 
                FROM information_schema.table_constraints 
                WHERE constraint_schema = 'qa' 
                AND table_name = 'ecomm_tenant_admins_company' 
                AND constraint_name = 'ecomm_tenant_admins_company_client_id_fk'
            ) THEN
                -- Add the foreign key constraint
                ALTER TABLE ecomm_tenant_admins_company 
                ADD CONSTRAINT ecomm_tenant_admins_company_client_id_fk 
                FOREIGN KEY (client_id) 
                REFERENCES ecomm_tenant_admin_crmclients(client_id)
                ON DELETE SET NULL;
            END IF;
        END $$;
    """)
    print("Foreign key constraint added successfully!")
    
    # Verify the changes
    cursor.execute("""
        SELECT constraint_name 
        FROM information_schema.table_constraints 
        WHERE constraint_schema = 'qa' 
        AND table_name = 'ecomm_tenant_admins_company' 
        AND constraint_name = 'ecomm_tenant_admins_company_client_id_fk';
    """)
    constraint_info = cursor.fetchone()
    if constraint_info:
        print(f"Foreign key constraint exists: {constraint_info[0]}")
    else:
        print("Foreign key constraint does not exist!")
    
    # Reset search path
    cursor.execute("SET search_path TO public;")
    
except Exception as e:
    print(f"An error occurred: {e}")
finally:
    # Close the cursor and connection
    if 'cursor' in locals():
        cursor.close()
    conn.close()
    print("Database connection closed.")
