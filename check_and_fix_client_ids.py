"""
Script to check existing client_id values in the company table
and create corresponding records in the TenantCrmClient table before
adding the foreign key constraint.
"""
import os
import psycopg2
from django.conf import settings
import django
from datetime import datetime

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
    
    # Check if the client_id column exists in the company table
    cursor.execute("""
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_schema = 'qa' 
        AND table_name = 'ecomm_tenant_admins_company' 
        AND column_name = 'client_id';
    """)
    column_exists = cursor.fetchone() is not None
    
    if column_exists:
        print("client_id column exists in the company table.")
        
        # Get all distinct client_id values from the company table
        cursor.execute("""
            SELECT DISTINCT client_id 
            FROM ecomm_tenant_admins_company 
            WHERE client_id IS NOT NULL;
        """)
        client_ids = [row[0] for row in cursor.fetchall()]
        print(f"Found client_id values in the company table: {client_ids}")
        
        # Check which client_ids don't exist in the TenantCrmClient table
        missing_client_ids = []
        for client_id in client_ids:
            cursor.execute("""
                SELECT client_id 
                FROM ecomm_tenant_admin_crmclients 
                WHERE client_id = %s;
            """, (client_id,))
            if cursor.fetchone() is None:
                missing_client_ids.append(client_id)
        
        print(f"Missing client_ids in TenantCrmClient table: {missing_client_ids}")
        
        # Create missing client records
        for client_id in missing_client_ids:
            print(f"Creating TenantCrmClient record for client_id: {client_id}")
            cursor.execute("""
                INSERT INTO ecomm_tenant_admin_crmclients (
                    client_id, 
                    client_name, 
                    contactperson_email, 
                    created_by, 
                    created_at, 
                    updated_by, 
                    updated_at
                ) VALUES (
                    %s, 
                    'Auto-created Client ' || %s, 
                    'auto-created@example.com', 
                    'system@turtlesoftware.co', 
                    NOW(), 
                    'system@turtlesoftware.co', 
                    NOW()
                );
            """, (client_id, client_id))
            print(f"Created TenantCrmClient record for client_id: {client_id}")
    else:
        print("client_id column does not exist in the company table.")
    
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
