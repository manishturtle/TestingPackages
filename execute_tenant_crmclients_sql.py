"""
Script to execute the SQL file that creates the tenant CRM clients table
and inserts the initial record in the 'qa' schema.
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
    with open('create_tenant_crmclients_table.sql', 'r') as f:
        sql_script = f.read()
    
    # Execute the SQL script
    print("Executing SQL script...")
    cursor.execute(sql_script)
    print("SQL script executed successfully!")
    
    # Verify the table was created and data was inserted
    cursor.execute("SET search_path TO qa;")
    cursor.execute("SELECT * FROM ecomm_tenant_admins_crmclients;")
    rows = cursor.fetchall()
    
    print(f"Number of records in the table: {len(rows)}")
    for row in rows:
        print(f"Record: {row}")
    
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
