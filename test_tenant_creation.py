import os
import sys
import django
import json
from datetime import datetime, timedelta

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'KeyProductSettings.settings')
django.setup()

from ecomm_superadmin.models import Tenant, CrmClient
from ecomm_superadmin.serializers import TenantSerializer
from django.utils import timezone

def create_test_tenant():
    # First, make sure we have at least one CRM client
    try:
        client = CrmClient.objects.first()
        if not client:
            print("Creating a test CRM client first...")
            client = CrmClient.objects.create(
                client_name="Test Client",
                contact_person_email="test@example.com"
            )
            print(f"Created CRM client: {client.client_name} (ID: {client.id})")
        else:
            print(f"Using existing CRM client: {client.client_name} (ID: {client.id})")
        
        # Create a test tenant
        tenant_data = {
            'name': f'Test Tenant {timezone.now().strftime("%Y%m%d%H%M%S")}',
            'url_suffix': f'test-tenant-{timezone.now().strftime("%Y%m%d%H%M%S")}',
            'status': 'trial',
            'environment': 'development',
            'trial_end_date': (timezone.now() + timedelta(days=30)).date().isoformat(),
            'client_id': client.id,
            'admin_email': 'admin@testtenant.com',
            'admin_first_name': 'Test',
            'admin_last_name': 'Admin',
            'admin_password': 'password123'
        }
        
        print(f"Creating tenant with data: {json.dumps(tenant_data, indent=2, default=str)}")
        
        # Use the serializer to create the tenant
        serializer = TenantSerializer(data=tenant_data)
        if serializer.is_valid():
            tenant = serializer.save()
            print(f"Successfully created tenant: {tenant.name} (ID: {tenant.id})")
            print(f"Schema name: {tenant.schema_name}")
            print(f"Trial end date: {tenant.trial_end_date}")
            print(f"CRM client: {tenant.client.client_name if tenant.client else 'None'}")
            return True
        else:
            print(f"Error creating tenant: {serializer.errors}")
            return False
    except Exception as e:
        print(f"Exception: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = create_test_tenant()
    sys.exit(0 if success else 1)
