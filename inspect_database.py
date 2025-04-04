import os
import django
import sys
import json
import requests

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'KeyProductSettings.settings')
django.setup()

from django.db import connection
from django.conf import settings
from ecomm_superadmin.models import Client, Domain
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def inspect_database():
    """
    Inspect the database tables and check the tenant admin API endpoint.
    """
    try:
        # Make sure we're in the public schema
        connection.set_schema_to_public()
        
        # 1. Check Domain model configuration
        logger.info("=== Checking Domain model configuration ===")
        logger.info(f"TENANT_MODEL: {settings.TENANT_MODEL}")
        logger.info(f"TENANT_DOMAIN_MODEL: {settings.TENANT_DOMAIN_MODEL}")
        logger.info(f"TENANT_SUBFOLDER_PREFIX: {settings.TENANT_SUBFOLDER_PREFIX}")
        logger.info(f"TENANT_SUBFOLDER_URLS: {getattr(settings, 'TENANT_SUBFOLDER_URLS', False)}")
        
        # Get all domains
        domains = Domain.objects.all()
        logger.info(f"Found {domains.count()} domain records:")
        for domain in domains:
            tenant_name = domain.tenant.name if domain.tenant else "None"
            folder_display = domain.folder if domain.folder else "NULL"
            logger.info(f"Domain: {domain.domain}, Folder: {folder_display}, Tenant: {tenant_name}")
        
        # 2. Check the 'qa' tenant schema
        logger.info("\n=== Checking 'qa' tenant schema ===")
        try:
            qa_tenant = Client.objects.get(schema_name='qa')
            logger.info(f"Found 'qa' tenant: {qa_tenant.name} (schema: {qa_tenant.schema_name})")
            
            # Switch to the 'qa' schema
            connection.set_tenant(qa_tenant)
            
            # Inspect database tables
            with connection.cursor() as cursor:
                # Get a list of tables in the current schema
                cursor.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'qa'
                ORDER BY table_name;
                """)
                tables = cursor.fetchall()
                
                logger.info(f"Found {len(tables)} tables in 'qa' schema:")
                for table in tables:
                    logger.info(f"  {table[0]}")
                
                # Check the auth_user table structure
                logger.info("\nChecking auth_user table structure:")
                try:
                    cursor.execute("""
                    SELECT column_name, data_type 
                    FROM information_schema.columns 
                    WHERE table_schema = 'qa' AND table_name = 'auth_user'
                    ORDER BY ordinal_position;
                    """)
                    columns = cursor.fetchall()
                    
                    logger.info(f"Found {len(columns)} columns in auth_user table:")
                    for column in columns:
                        logger.info(f"  {column[0]} ({column[1]})")
                    
                    # Check if there are any users in the auth_user table
                    cursor.execute("SELECT COUNT(*) FROM qa.auth_user;")
                    user_count = cursor.fetchone()[0]
                    logger.info(f"Found {user_count} users in auth_user table")
                    
                    if user_count > 0:
                        cursor.execute("SELECT id, email, is_staff FROM qa.auth_user LIMIT 5;")
                        users = cursor.fetchall()
                        logger.info("Sample users:")
                        for user in users:
                            logger.info(f"  ID: {user[0]}, Email: {user[1]}, Is Staff: {user[2]}")
                except Exception as e:
                    logger.error(f"Error checking auth_user table: {str(e)}")
                
                # Check the ecomm_tenant_admins_userprofile table
                logger.info("\nChecking ecomm_tenant_admins_userprofile table:")
                try:
                    cursor.execute("""
                    SELECT column_name, data_type 
                    FROM information_schema.columns 
                    WHERE table_schema = 'qa' AND table_name = 'ecomm_tenant_admins_userprofile'
                    ORDER BY ordinal_position;
                    """)
                    columns = cursor.fetchall()
                    
                    logger.info(f"Found {len(columns)} columns in ecomm_tenant_admins_userprofile table:")
                    for column in columns:
                        logger.info(f"  {column[0]} ({column[1]})")
                    
                    # Check if there are any profiles
                    cursor.execute("SELECT COUNT(*) FROM qa.ecomm_tenant_admins_userprofile;")
                    profile_count = cursor.fetchone()[0]
                    logger.info(f"Found {profile_count} profiles in ecomm_tenant_admins_userprofile table")
                    
                    if profile_count > 0:
                        cursor.execute("SELECT id, user_id, is_tenant_admin FROM qa.ecomm_tenant_admins_userprofile LIMIT 5;")
                        profiles = cursor.fetchall()
                        logger.info("Sample profiles:")
                        for profile in profiles:
                            logger.info(f"  ID: {profile[0]}, User ID: {profile[1]}, Is Tenant Admin: {profile[2]}")
                except Exception as e:
                    logger.error(f"Error checking ecomm_tenant_admins_userprofile table: {str(e)}")
        
        except Client.DoesNotExist:
            logger.error("'qa' tenant not found")
        
        # 3. Test the API endpoint directly
        logger.info("\n=== Testing API endpoint directly ===")
        
        # Reset to public schema
        connection.set_schema_to_public()
        
        # Test email
        test_email = "ankit@quickassist.co.in"
        
        # API endpoint URL
        api_url = "http://localhost:8000/api/qa/tenant-admin/auth/check-user/"
        
        # Headers
        headers = {
            'Content-Type': 'application/json',
            'X-Tenant-Admin': 'true',
            'X-Tenant-Name': 'qa'
        }
        
        # Payload
        payload = {
            'email': test_email
        }
        
        logger.info(f"Making API request to: {api_url}")
        logger.info(f"Headers: {headers}")
        logger.info(f"Payload: {payload}")
        
        try:
            response = requests.post(api_url, json=payload, headers=headers)
            logger.info(f"Response status code: {response.status_code}")
            logger.info(f"Response content: {response.text}")
            
            # Parse the response
            if response.status_code == 200:
                logger.info("API call successful!")
                try:
                    data = response.json()
                    logger.info(f"Parsed response: {data}")
                except json.JSONDecodeError:
                    logger.error("Failed to parse JSON response")
            else:
                logger.error(f"API call failed with status code: {response.status_code}")
        except Exception as e:
            logger.error(f"Error making API request: {str(e)}")
        
        logger.info("\nInspection completed.")
    
    except Exception as e:
        logger.error(f"Error during inspection: {str(e)}")

if __name__ == "__main__":
    inspect_database()
