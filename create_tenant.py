import os
import django

# Set up Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "erp_project.settings")
django.setup()

# Import models after Django setup
from authentication.models import Client, Domain
from django.contrib.auth.models import User

# Create or get the 'qa' tenant
try:
    client = Client.objects.get(schema_name='qa')
    print(f"Found existing tenant: {client.name} ({client.schema_name})")
except Client.DoesNotExist:
    client = Client(
        schema_name='qa',
        name='QA Tenant',
        url_suffix='qa'
    )
    client.save()
    print(f"Created new tenant: {client.name} ({client.schema_name})")

# Create or get domain for the tenant
try:
    domain = Domain.objects.get(tenant=client, domain='localhost')
    print(f"Found existing domain: {domain.domain} for tenant {client.name}")
except Domain.DoesNotExist:
    domain = Domain(
        domain='localhost',
        tenant=client,
        is_primary=True
    )
    domain.save()
    print(f"Created new domain: {domain.domain} for tenant {client.name}")

print("Tenant and domain setup complete!")
