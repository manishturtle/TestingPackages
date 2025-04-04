"""
Script to fix the Tenant API by directly querying the database and returning the results.
This bypasses Django's ORM to avoid field name mapping issues.
"""
import os
import sys
import django
import json
from datetime import datetime, date

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'KeyProductSettings.settings')
django.setup()

# Import Django modules
from django.db import connection
from django.http import JsonResponse
from django.urls import path
from django.conf.urls import include
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.handlers.wsgi import WSGIHandler
from django.core.servers.basehttp import WSGIServer
from django.core.management import call_command

def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

def is_admin(user):
    """Check if the user is an admin"""
    return user.is_staff

@login_required
@user_passes_test(is_admin)
def get_tenants(request):
    """
    Get all tenants directly from the database.
    This bypasses Django's ORM to avoid field name mapping issues.
    """
    try:
        with connection.cursor() as cursor:
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
                
                # Add subscription plan details if available
                if tenant_dict.get('subscription_plan_id'):
                    cursor.execute("""
                        SELECT id, name, description, price, max_users, max_storage
                        FROM ecomm_superadmin_subscriptionplan
                        WHERE id = %s
                    """, [tenant_dict['subscription_plan_id']])
                    plan_columns = [col[0] for col in cursor.description]
                    plan_row = cursor.fetchone()
                    if plan_row:
                        tenant_dict['subscription_plan'] = dict(zip(plan_columns, plan_row))
                
                # Add client details if available
                if tenant_dict.get('client_id'):
                    cursor.execute("""
                        SELECT id, client_name, contact_person_email
                        FROM ecomm_superadmin_crmclients
                        WHERE id = %s
                    """, [tenant_dict['client_id']])
                    client_columns = [col[0] for col in cursor.description]
                    client_row = cursor.fetchone()
                    if client_row:
                        tenant_dict['client'] = dict(zip(client_columns, client_row))
                
                tenants.append(tenant_dict)
            
            return JsonResponse(tenants, safe=False, json_dumps_params={'default': json_serial})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({"error": str(e)}, status=500)

def fix_tenant_api():
    """
    Apply the fix to the Tenant API by updating the URL configuration.
    """
    # Update the URL configuration
    from django.urls import path, include
    from django.conf.urls import url
    
    # Import the original URL patterns
    from ecomm_superadmin.admin_urls import urlpatterns as admin_urlpatterns
    
    # Add our custom view
    admin_urlpatterns.append(
        path('tenants-fixed/', get_tenants, name='admin-tenant-list-fixed')
    )
    
    print("Tenant API fix applied. You can now access the fixed API at /platform-admin/api/tenants-fixed/")
    print("Run the server with 'python manage.py runserver' to test the fix.")

if __name__ == "__main__":
    fix_tenant_api()
    
    # Run the server
    call_command('runserver')
