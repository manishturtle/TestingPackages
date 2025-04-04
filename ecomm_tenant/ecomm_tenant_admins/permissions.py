from functools import wraps
from django.http import HttpResponseForbidden
from rest_framework import permissions
from ecomm_tenant.ecomm_tenant_admins.models import TenantUser
import logging

logger = logging.getLogger(__name__)

class IsTenantAdmin(permissions.BasePermission):
    """
    Custom permission to only allow tenant administrators to access the view.
    
    This permission class specifically checks:
    1. If the user is authenticated
    2. If the user has is_staff=True
    3. If the user has is_tenant_admin=True in their UserProfile
    
    It also checks JWT token claims for is_tenant_admin and is_staff.
    """
    message = "Only tenant administrators are authorized to perform this action."
    
    def has_permission(self, request, view):
        """
        Check if the user is authenticated and is a tenant admin.
        """
        logger.info(f"IsTenantAdmin checking permission for: {request.user} on {request.path}")
        
        # First check if the user is authenticated
        if not request.user.is_authenticated:
            logger.warning(f"Permission denied: User is not authenticated - {request.user}")
            return False
        
        # Check JWT token for tenant admin claims if using JWT authentication
        from rest_framework_simplejwt.authentication import JWTAuthentication
        jwt_auth = JWTAuthentication()
        
        try:
            # Get the JWT token from the request
            header = jwt_auth.get_header(request)
            if header:
                raw_token = jwt_auth.get_raw_token(header)
                if raw_token:
                    validated_token = jwt_auth.get_validated_token(raw_token)
                    logger.info(f"JWT token claims: {validated_token}")
                    
                    # Check if the token has tenant admin claims
                    is_tenant_admin_in_token = validated_token.get('is_tenant_admin', False)
                    is_staff_in_token = validated_token.get('is_staff', False)
                    
                    logger.info(f"Token claims - is_tenant_admin: {is_tenant_admin_in_token}, is_staff: {is_staff_in_token}")
                    
                    if is_tenant_admin_in_token and is_staff_in_token:
                        logger.info(f"Permission granted via JWT token claims: User is a valid tenant admin")
                        return True
        except Exception as e:
            logger.warning(f"Error checking JWT token: {str(e)}")
            # Continue with database checks if JWT validation fails
        
        # Then check if the user has is_staff=True
        if not hasattr(request.user, 'is_staff') or not request.user.is_staff:
            logger.warning(f"Permission denied: User does not have is_staff=True - {request.user}")
            return False
        
        # Then check if the user has a profile with is_tenant_admin=True
        try:
            from ecomm_tenant.ecomm_tenant_admins.models import UserProfile
            profile = UserProfile.objects.get(user=request.user)
            
            if profile.is_tenant_admin:
                logger.info(f"Permission granted: User {request.user.email} is a valid tenant admin")
                return True
            else:
                logger.warning(f"Permission denied: User profile does not have is_tenant_admin=True - {request.user}")
                return False
        except UserProfile.DoesNotExist:
            logger.warning(f"Permission denied: User has no profile - {request.user}")
            return False
        except AttributeError as e:
            logger.warning(f"Permission denied: AttributeError - {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Error checking tenant admin status: {str(e)}", exc_info=True)
            return False
            
    def has_object_permission(self, request, view, obj):
        """
        Check if the user is a tenant admin for the specific object.
        This is a more granular check that can be used for specific objects.
        """
        # First check if the user is authenticated and is a tenant admin
        if not self.has_permission(request, view):
            return False
            
        # For now, any tenant admin can access any object within their tenant
        # This is because tenant isolation is handled at the database level
        # through the tenant_schemas middleware
        return True

class IsCurrentTenantAdmin(permissions.BasePermission):
    """
    Custom permission to only allow current tenant administrators to access the view.
    
    This permission class specifically checks:
    1. If the user is authenticated
    2. If the request has a tenant attribute (set by TenantRoutingMiddleware)
    3. If the user is an instance of TenantUser (not the shared ecomm_superadmin.User)
    4. If the user has is_staff=True (indicating tenant admin status)
    5. If the user has is_tenant_admin=True in their UserProfile
    
    This ensures that only proper tenant admins from the current tenant schema
    can access the protected views, not platform admins from the public schema.
    """
    message = "Only tenant administrators from the current tenant are authorized to perform this action."
    
    def has_permission(self, request, view):
        """
        Check if the user is authenticated, is a TenantUser instance, and is a tenant admin.
        """
        # Log the request details for debugging
        logger.info(f"IsCurrentTenantAdmin checking permission for: {request.user} on {request.path}")
        logger.info(f"Request tenant: {getattr(request, 'tenant', None)}")
        
        # Check if the X-Tenant-Admin header is present and set to 'true'
        is_tenant_admin_request = request.META.get('HTTP_X_TENANT_ADMIN', '').lower() == 'true'
        if is_tenant_admin_request:
            logger.info("Request has X-Tenant-Admin header set to true")
        
        # Check if the user is authenticated
        if not request.user.is_authenticated:
            logger.warning(f"Permission denied: User is not authenticated - {request.user}")
            return False
        
        # Check if request has a tenant attribute (set by TenantRoutingMiddleware)
        if not hasattr(request, 'tenant'):
            logger.warning(f"Permission denied: Request has no tenant attribute - {request.path}")
            return False
        
        # Check JWT token for tenant admin claims if using JWT authentication
        from rest_framework_simplejwt.authentication import JWTAuthentication
        jwt_auth = JWTAuthentication()
        
        try:
            # Get the JWT token from the request
            header = jwt_auth.get_header(request)
            if header:
                raw_token = jwt_auth.get_raw_token(header)
                if raw_token:
                    validated_token = jwt_auth.get_validated_token(raw_token)
                    logger.info(f"JWT token claims: {validated_token}")
                    
                    # Check if the token has tenant admin claims
                    is_tenant_admin_in_token = validated_token.get('is_tenant_admin', False)
                    is_staff_in_token = validated_token.get('is_staff', False)
                    
                    logger.info(f"Token claims - is_tenant_admin: {is_tenant_admin_in_token}, is_staff: {is_staff_in_token}")
                    
                    if is_tenant_admin_in_token and is_staff_in_token:
                        # Check if the token's tenant matches the request tenant
                        token_tenant_slug = validated_token.get('tenant_slug')
                        if token_tenant_slug and token_tenant_slug == request.tenant.url_suffix:
                            logger.info(f"Permission granted via JWT token claims: User is a valid tenant admin for tenant {token_tenant_slug}")
                            return True
                        else:
                            logger.warning(f"Permission denied: Token tenant slug '{token_tenant_slug}' does not match request tenant '{request.tenant.url_suffix}'")
                    else:
                        logger.warning(f"Permission denied: Token does not have required tenant admin claims")
        except Exception as e:
            logger.warning(f"Error checking JWT token: {str(e)}")
            # Continue with database checks if JWT validation fails
        
        # If JWT validation fails or no token, check database records
        try:
            # Check if the user is a TenantUser instance (not a platform admin)
            from ecomm_tenant.ecomm_tenant_admins.models import TenantUser, UserProfile
            if not isinstance(request.user, TenantUser):
                logger.warning(f"Permission denied: User is not a TenantUser instance - {type(request.user)}")
                return False
            
            # Check if the user has is_staff=True (tenant admin status)
            if not request.user.is_staff:
                logger.warning(f"Permission denied: User does not have is_staff=True - {request.user}")
                return False
            
            # Check if the user has a profile with is_tenant_admin=True
            try:
                profile = UserProfile.objects.get(user=request.user)
                if not profile.is_tenant_admin:
                    logger.warning(f"Permission denied: User profile does not have is_tenant_admin=True - {request.user}")
                    return False
                
                logger.info(f"Permission granted: User {request.user.email} is a valid tenant admin")
                return True
            except UserProfile.DoesNotExist:
                logger.warning(f"Permission denied: User has no profile - {request.user}")
                return False
        except Exception as e:
            logger.error(f"Error checking tenant admin status: {str(e)}", exc_info=True)
            return False
    
    def has_object_permission(self, request, view, obj):
        """
        Check if the user has permission to access the specific object.
        """
        # First check basic permission
        if not self.has_permission(request, view):
            return False
            
        # For now, any tenant admin from the current tenant can access any object
        # within their tenant, as tenant isolation is handled at the database level
        return True

class HasTenantPermission(permissions.BasePermission):
    """
    Custom permission to check if a user has a specific permission through their roles.
    """
    
    def __init__(self, required_permission):
        self.required_permission = required_permission
        self.message = f"You don't have the required permission: {required_permission}"
    
    def has_permission(self, request, view):
        """
        Check if the user has the required permission.
        """
        # First check if the user is authenticated
        if not request.user.is_authenticated:
            logger.warning(f"Permission denied: User is not authenticated - {request.user}")
            return False
            
        # Check if request has a tenant attribute (set by TenantRoutingMiddleware)
        if not hasattr(request, 'tenant'):
            logger.warning(f"Permission denied: Request has no tenant attribute - {request.path}")
            return False
        
        # If the user is a tenant admin, grant permission automatically
        # This is a fallback to ensure tenant admins can access all features
        try:
            # Check if the user is an instance of TenantUser
            if not isinstance(request.user, TenantUser):
                logger.warning(f"Permission denied: User is not a TenantUser instance - {request.user}")
                return False
                
            # Check if the user has a profile with is_tenant_admin=True
            from ecomm_tenant.ecomm_tenant_admins.models import UserProfile
            profile = UserProfile.objects.get(user=request.user)
            
            if profile.is_tenant_admin and request.user.is_staff:
                logger.info(f"Permission granted: User {request.user.email} is a tenant admin")
                return True
        except Exception as e:
            logger.warning(f"Error checking tenant admin status: {str(e)}")
            # Continue with permission check
        
        # Check if the user has the specific permission through their roles
        try:
            from .utils import has_permission
            has_perm = has_permission(request.user, self.required_permission)
            if has_perm:
                logger.info(f"Permission granted: User {request.user.email} has permission {self.required_permission}")
            else:
                logger.warning(f"Permission denied: User {request.user.email} does not have permission {self.required_permission}")
            return has_perm
        except Exception as e:
            logger.error(f"Error checking permission {self.required_permission}: {str(e)}", exc_info=True)
            # If there's an error checking permissions, deny access
            return False
    
    def has_object_permission(self, request, view, obj):
        """
        Check if the user has the required permission for the specific object.
        """
        return self.has_permission(request, view)

def tenant_admin_required(view_func):
    """
    Decorator for views that checks if the user is a tenant admin.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        # Check if the user is authenticated
        if not request.user.is_authenticated:
            return HttpResponseForbidden("Authentication required")
            
        # Check if the user is a tenant admin
        try:
            if request.user.profile.is_tenant_admin:
                return view_func(request, *args, **kwargs)
        except AttributeError:
            pass
            
        return HttpResponseForbidden("Only tenant administrators are authorized to access this page")
    
    return _wrapped_view

def permission_required(permission_codename):
    """
    Decorator for views that checks if the user has a specific permission.
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            # Check if the user has the required permission
            from .utils import has_permission
            if has_permission(request.user, permission_codename):
                return view_func(request, *args, **kwargs)
                
            return HttpResponseForbidden(f"You don't have the required permission: {permission_codename}")
        
        return _wrapped_view
    
    return decorator
