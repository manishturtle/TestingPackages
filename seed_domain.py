import os
import django
import sys

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'KeyProductSettings.settings')
django.setup()

from django.db import connection
from ecomm_superadmin.models import Client, Domain

def seed_domain():
    """
    Seed a domain record for the 'qa' tenant with subfolder support.
    """
    try:
        # Make sure we're in the public schema
        connection.set_schema_to_public()
        
        # Check if the qa tenant exists
        try:
            qa_tenant = Client.objects.get(schema_name='qa')
            print(f"Found existing tenant: {qa_tenant.name} (schema: {qa_tenant.schema_name})")
        except Client.DoesNotExist:
            print("Error: The 'qa' tenant does not exist. Please create it first.")
            return
        
        # Check if a domain already exists for this tenant
        existing_domain = Domain.objects.filter(domain='localhost').first()
        
        if existing_domain:
            # Update the existing domain
            existing_domain.tenant = qa_tenant
            existing_domain.folder = 'qa'
            existing_domain.is_primary = True
            existing_domain.save()
            print(f"Updated existing domain: {existing_domain}")
        else:
            # Create a new domain
            domain = Domain.objects.create(
                tenant=qa_tenant,
                domain='localhost',
                folder='qa',
                is_primary=True
            )
            print(f"Created new domain: {domain}")
        
        print("Domain seeding completed successfully.")
    
    except Exception as e:
        print(f"Error seeding domain: {str(e)}")

if __name__ == "__main__":
    seed_domain()
