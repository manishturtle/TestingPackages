"""
Script to execute the SQL file that updates the company-client relationship
in the 'qa' schema.
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
    with open('update_company_client_relationship.sql', 'r') as f:
        sql_script = f.read()
    
    # Execute the SQL script
    print("Executing SQL script to update company-client relationship...")
    cursor.execute(sql_script)
    print("SQL script executed successfully!")
    
    # Verify the changes
    cursor.execute("SET search_path TO qa;")
    
    # Check if the client_id column exists
    cursor.execute("""
        SELECT column_name, data_type 
        FROM information_schema.columns 
        WHERE table_schema = 'qa' 
        AND table_name = 'ecomm_tenant_admins_company' 
        AND column_name = 'client_id';
    """)
    column_info = cursor.fetchone()
    if column_info:
        print(f"Column client_id exists with data type: {column_info[1]}")
    else:
        print("Column client_id does not exist!")
    
    # Check if the foreign key constraint exists
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
