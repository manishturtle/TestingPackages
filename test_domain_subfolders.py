import os
import django
import sys

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'KeyProductSettings.settings')
django.setup()

from django.db import connection
from ecomm_superadmin.models import Client, Domain

def test_domain_subfolders():
    """
    Test the updated Domain model by creating multiple domain records with the same domain
    but different folders.
    """
    try:
        # Make sure we're in the public schema
        connection.set_schema_to_public()
        
        # Get the qa tenant
        try:
            qa_tenant = Client.objects.get(schema_name='qa')
            print(f"Found existing tenant: {qa_tenant.name} (schema: {qa_tenant.schema_name})")
        except Client.DoesNotExist:
            print("Error: The 'qa' tenant does not exist. Please create it first.")
            return
        
        # Create a test tenant if it doesn't exist
        acme_tenant, created = Client.objects.get_or_create(
            schema_name='acme',
            defaults={
                'name': 'ACME Corporation',
                'url_suffix': 'acme'
            }
        )
        if created:
            print(f"Created new tenant: {acme_tenant.name} (schema: {acme_tenant.schema_name})")
        else:
            print(f"Found existing tenant: {acme_tenant.name} (schema: {acme_tenant.schema_name})")
        
        # Create domain records with the same domain but different folders
        
        # 1. Update or create the 'qa' folder domain
        qa_domain, created = Domain.objects.update_or_create(
            domain='localhost',
            folder='qa',
            defaults={
                'tenant': qa_tenant,
                'is_primary': True
            }
        )
        if created:
            print(f"Created new domain: {qa_domain}")
        else:
            print(f"Updated existing domain: {qa_domain}")
        
        # 2. Create the 'acme' folder domain
        acme_domain, created = Domain.objects.update_or_create(
            domain='localhost',
            folder='acme',
            defaults={
                'tenant': acme_tenant,
                'is_primary': True
            }
        )
        if created:
            print(f"Created new domain: {acme_domain}")
        else:
            print(f"Updated existing domain: {acme_domain}")
        
        print("\nDomain subfolder test completed successfully.")
    
    except Exception as e:
        print(f"Error testing domain subfolders: {str(e)}")

if __name__ == "__main__":
    test_domain_subfolders()
