# ecomm_product/urls_public.py
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls), # Django admin for public schema
    path('platform-admin/api/', include('ecomm_superadmin.admin_urls')), # Your platform admin APIs
    
    # Add any other URLs specific to the public/main website here
    # Note: Tenant-specific URLs should be in urls.py, not here
]
