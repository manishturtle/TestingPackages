"""
Script to execute the SQL file that renames the tenant CRM clients table and column
in all tenant schemas.
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
    
    # Read the SQL file
    with open('rename_tenant_crmclients.sql', 'r') as f:
        sql_script = f.read()
    
    # Execute the SQL script
    print("Executing SQL script to rename table and column in all tenant schemas...")
    cursor.execute(sql_script)
    print("SQL script executed successfully!")
    
    # Verify the changes in the 'qa' schema
    cursor.execute("SET search_path TO qa;")
    
    # Check if the new table exists
    cursor.execute("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'ecomm_tenant_admins_crmclients');")
    table_exists = cursor.fetchone()[0]
    
    if table_exists:
        print("✅ Table renamed successfully to ecomm_tenant_admins_crmclients in 'qa' schema")
        
        # Check if the column was renamed
        cursor.execute("SELECT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'ecomm_tenant_admins_crmclients' AND column_name = 'contact_person_email');")
        column_exists = cursor.fetchone()[0]
        
        if column_exists:
            print("✅ Column renamed successfully to contact_person_email in 'qa' schema")
            
            # Show the data in the table
            cursor.execute("SELECT * FROM ecomm_tenant_admins_crmclients;")
            rows = cursor.fetchall()
            
            print(f"Number of records in the table: {len(rows)}")
            for row in rows:
                print(f"Record: {row}")
        else:
            print("❌ Column rename failed in 'qa' schema")
    else:
        print("❌ Table rename failed in 'qa' schema")
    
    # Reset search path
    cursor.execute("SET search_path TO public;")
    
except Exception as e:
    print(f"Error executing SQL script: {str(e)}")
    
finally:
    # Close the cursor and connection
    cursor.close()
    conn.close()
    print("Database connection closed.")
