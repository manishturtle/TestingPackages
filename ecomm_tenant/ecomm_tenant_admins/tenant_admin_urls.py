# ecomm_tenant/ecomm_tenant_admins/tenant_admin_urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    CheckEmailView, RegisterUserView, UserProfileView, LoginView, 
    CheckUserExistsView, VerifyOtpView, ResendOtpView, 
    SignupVerifyAndCompleteView, TenantAdminVerifyView,
    RoleViewSet, PermissionViewSet, UserRoleViewSet, TenantUserViewSet
)
from .views_2fa import TwoFactorSetupStartView, TwoFactorSetupConfirmView, TwoFactorVerifyView, TwoFactorRecoveryVerifyView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

# Create a router for viewsets
router = DefaultRouter()
# Register role-related viewsets
router.register(r'roles', RoleViewSet, basename='role')
router.register(r'permissions', PermissionViewSet, basename='permission')
router.register(r'user-roles', UserRoleViewSet, basename='user-role')
# Register user management viewset
router.register(r'users', TenantUserViewSet, basename='tenant-user')

# Consolidated urlpatterns for tenant admin
urlpatterns = [
    # Include the router URLs
    path('', include(router.urls)),
    
    # JWT Token endpoints
    path('token/', TokenObtainPairView.as_view(), name='tenant_token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='tenant_token_refresh'),
    
    # Authentication endpoints
    path('auth/check-user/', CheckUserExistsView.as_view(), name='check-user'),
    path('auth/login/', LoginView.as_view(), name='login'),
    path('auth/verify-otp/', VerifyOtpView.as_view(), name='verify-otp'),
    path('auth/resend-otp/', ResendOtpView.as_view(), name='resend-otp'),
    
    # User management
    path('check-email/', CheckEmailView.as_view(), name='check-email'),
    path('register/', RegisterUserView.as_view(), name='register'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('signup/verify-and-complete/', SignupVerifyAndCompleteView.as_view(), name='signup-verify-and-complete'),
    
    # 2FA endpoints
    path('2fa/setup/start/', TwoFactorSetupStartView.as_view(), name='2fa-setup-start'),
    path('2fa/setup/confirm/', TwoFactorSetupConfirmView.as_view(), name='2fa-setup-confirm'),
    path('2fa/auth/', TwoFactorVerifyView.as_view(), name='2fa-verify'),
    path('2fa/recovery-auth/', TwoFactorRecoveryVerifyView.as_view(), name='2fa-recovery-verify'),
    
    # Tenant Admin verification
    path('tenant-admin/auth/', TenantAdminVerifyView.as_view(), name='tenant-admin-verify'),
]

# Special endpoint for tenant admin roles - this will be accessible at the root level
urlpatterns += [
    path('tenant-admin-roles/', RoleViewSet.as_view({'get': 'tenant_admin_roles'}), name='tenant-admin-roles'),
    path('debug-roles/', RoleViewSet.as_view({'get': 'debug_roles'}), name='debug-roles'),
]
