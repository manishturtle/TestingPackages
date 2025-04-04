import os
import django

# Set up Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "erp_project.settings")
django.setup()

# Import models after Django setup
from authentication.models import Client, UserProfile, Company
from django.contrib.auth.models import User
from django_tenants.utils import tenant_context, schema_context

# Get the 'qa' tenant
try:
    client = Client.objects.get(schema_name='qa')
    print(f"Found tenant: {client.name} ({client.schema_name})")
    
    # Switch to tenant context
    with schema_context(client.schema_name):
        # Create a company in the tenant schema
        try:
            company = Company.objects.get(name='QA Company')
            print(f"Company already exists: {company.name}")
        except Company.DoesNotExist:
            company = Company.objects.create(
                name='QA Company',
                client=client
            )
            print(f"Created company: {company.name}")
            
        # Create a user in the tenant schema
        try:
            user = User.objects.get(username='admin@qa.com')
            print(f"User already exists: {user.username}")
        except User.DoesNotExist:
            user = User.objects.create_user(
                username='admin@qa.com',
                email='admin@qa.com',
                password='password123',
                first_name='Admin',
                last_name='User'
            )
            user.is_staff = True
            user.is_superuser = True
            user.save()
            print(f"Created user: {user.username}")
            
        # Create user profile
        try:
            profile = UserProfile.objects.get(user=user)
            print(f"Profile already exists for {user.username}")
        except UserProfile.DoesNotExist:
            profile = UserProfile(
                user=user,
                company=company,
                is_tenant_admin=True,
                is_email_verified=True
            )
            profile.save()
            print(f"Created profile for {user.username} with tenant admin privileges")
                
        print(f"Tenant admin setup complete for {client.name}!")
        
except Client.DoesNotExist:
    print("Tenant 'qa' not found. Please create the tenant first.")
