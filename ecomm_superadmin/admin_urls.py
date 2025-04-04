from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import PlatformAdminTenantView, PlatformAdminLoginView, PlatformAdminCheckUserExistsView, PlatformAdminViewSet, CrmClientViewSet

#from .views_2fa import TwoFactorVerifyView, TwoFactorRecoveryVerifyView
#from ecomm_tenant.ecomm_tenant_admins.views_2fa import TwoFactorVerifyView, TwoFactorRecoveryVerifyView # Corrected import path
# Create a router for admin viewsets
admin_router = DefaultRouter()
# admin_router.register(r'tenants', PlatformAdminTenantViewSet, basename='admin-tenant')  # Commented out the ViewSet
admin_router.register(r'users', PlatformAdminViewSet, basename='admin-user')
admin_router.register(r'crmclients', CrmClientViewSet, basename='admin-crmclient')

urlpatterns = [
    # Include the router URLs
    path('', include(admin_router.urls)),
    
    # Add direct path for tenants
    path('tenants/', PlatformAdminTenantView.as_view(), name='admin-tenant-list'),
    path('tenants/<int:tenant_id>/', PlatformAdminTenantView.as_view(), name='admin-tenant-detail'),
    
    # Authentication URLs for platform admins
    path('auth/login/', PlatformAdminLoginView.as_view(), name='platform-admin-login'),
    path('auth/check-user/', PlatformAdminCheckUserExistsView.as_view(), name='platform-admin-check-user'),
   # path('auth/2fa/auth/', TwoFactorVerifyView.as_view(), name='platform-admin-2fa-verify'),
   # path('auth/2fa/recovery-auth/', TwoFactorRecoveryVerifyView.as_view(), name='platform-admin-2fa-recovery-verify'),
]
