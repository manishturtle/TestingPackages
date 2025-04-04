"""
Simple script to test direct database access to the tenants table.
This bypasses Django's ORM to directly query the database.
"""
import os
import sys
import django
import psycopg2
import json
from datetime import datetime, date

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'KeyProductSettings.settings')
django.setup()

# Get database settings from Django
from django.conf import settings

db_settings = settings.DATABASES['default']

def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

def test_tenant_query():
    """Test querying the tenants table directly"""
    try:
        # Connect to the database
        conn = psycopg2.connect(
            dbname=db_settings['NAME'],
            user=db_settings['USER'],
            password=db_settings['PASSWORD'],
            host=db_settings['HOST'],
            port=db_settings['PORT']
        )
        
        # Create a cursor
        cursor = conn.cursor()
        
        # Get all tables in the database
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
            AND table_type = 'BASE TABLE'
        """)
        tables = [row[0] for row in cursor.fetchall()]
        print("Available tables:", tables)
        
        # Look for tenant-related tables
        tenant_tables = [table for table in tables if 'tenant' in table]
        print("Tenant-related tables:", tenant_tables)
        
        # Try to query the tenants table
        try:
            cursor.execute("""
                SELECT 
                    id, schema_name, name, description, url_suffix, created_at, updated_at,
                    status, environment, on_trial, trial_end_date, paid_until,
                    subscription_plan_id, tenant_admin_email, client_id
                FROM ecomm_superadmin_tenants
                ORDER BY created_at DESC
            """)
            
            # Get column names
            columns = [col[0] for col in cursor.description]
            
            # Fetch all rows
            rows = cursor.fetchall()
            
            # Convert rows to dictionaries
            tenants = []
            for row in rows:
                tenant_dict = dict(zip(columns, row))
                tenants.append(tenant_dict)
            
            # Print the results
            print(f"Found {len(tenants)} tenants:")
            print(json.dumps(tenants, indent=2, default=json_serial))
            
            # Check column names
            print("\nColumn names in the tenants table:")
            for col in columns:
                print(f"- {col}")
                
        except Exception as e:
            print(f"Error querying tenants table: {str(e)}")
            
            # Try to get the actual column names
            try:
                cursor.execute("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name = 'ecomm_superadmin_tenants'
                """)
                columns = [row[0] for row in cursor.fetchall()]
                print("Actual columns in ecomm_superadmin_tenants:", columns)
            except Exception as col_error:
                print(f"Error getting column names: {str(col_error)}")
        
        # Close the connection
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"Error connecting to database: {str(e)}")

if __name__ == "__main__":
    test_tenant_query()
