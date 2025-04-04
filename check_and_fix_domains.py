import os
import sys
import django

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'KeyProductSettings.settings')
django.setup()

from django.db import connection
from ecomm_superadmin.models import Client, Domain

def main():
    print("Checking and fixing domain configuration...")
    
    # Set schema to public to access tenant models
    connection.set_schema_to_public()
    
    # Check if 'qa' tenant exists
    try:
        qa_client = Client.objects.get(schema_name='qa')
        print(f"Found 'qa' tenant: {qa_client.schema_name}, name: {qa_client.name}")
        
        # Check if domain with folder='qa' exists
        try:
            domain = Domain.objects.get(folder='qa')
            print(f"Found domain with folder='qa': {domain.domain}, tenant: {domain.tenant.schema_name}")
        except Domain.DoesNotExist:
            print("No domain found with folder='qa'")
            
            # Check if any domains exist for the 'qa' tenant
            qa_domains = Domain.objects.filter(tenant=qa_client)
            if qa_domains.exists():
                print(f"Found {qa_domains.count()} domains for 'qa' tenant:")
                for domain in qa_domains:
                    print(f"  - Domain: {domain.domain}, folder: {domain.folder}")
                
                # Update the first domain to have folder='qa'
                domain = qa_domains.first()
                domain.folder = 'qa'
                domain.save()
                print(f"Updated domain {domain.domain} to have folder='qa'")
            else:
                # Create a new domain with folder='qa'
                domain = Domain(
                    domain='localhost',
                    folder='qa',
                    tenant=qa_client,
                    is_primary=True
                )
                domain.save()
                print(f"Created new domain with domain='localhost', folder='qa' for tenant 'qa'")
        
        # List all domains for verification
        print("\nAll domains in the database:")
        for domain in Domain.objects.all():
            print(f"  - Domain: {domain.domain}, folder: {domain.folder}, tenant: {domain.tenant.schema_name}")
        
    except Client.DoesNotExist:
        print("'qa' tenant does not exist. Please create it first.")

if __name__ == "__main__":
    main()
