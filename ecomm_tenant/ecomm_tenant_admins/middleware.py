from django.conf import settings
from django.db import connection
from django.http import Http404
from django.urls import resolve, Resolver404
from django.utils.deprecation import MiddlewareMixin
from ecomm_superadmin.models import Tenant, Domain
import re
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class TenantRoutingMiddleware(MiddlewareMixin):
    """
    Custom middleware to handle path-based routing in a multi-tenant application.
    
    This middleware extracts tenant slugs from URL paths and sets the appropriate schema
    for tenant-specific requests. It modifies the request path to remove the tenant slug
    so that the URL resolver can find the correct view.
    
    Supports three different URL patterns:
    1. /{tenant_slug}/ - For tenant users
    2. /{tenant_slug}/tenant-admin/ - For tenant admins
    3. /platform-admin/ - For platform admins
    """
    
    def __init__(self, get_response):
        """
        Initialize the middleware with the get_response callable.
        """
        self.get_response = get_response
        logger.info("TenantRoutingMiddleware initialized")
    
    def __call__(self, request):
        """
        Process each request to check for tenant-specific URLs.
        """
        # Get the request path
        path = request.path_info
        
        # Log every request for debugging
        logger.info(f"TenantRoutingMiddleware processing request: {path}")
        
        # Skip processing for Django admin, static, and media files
        if path.startswith('/admin/') or path.startswith('/static/') or path.startswith('/media/'):
            logger.info(f"Skipping admin/static/media path: {path}")
            return self.get_response(request)
        
        # Skip processing for platform admin routes
        if path.startswith('/platform-admin/') or path.startswith('/api/platform-admin/'):
            # Set schema to public for platform admin routes
            logger.info(f"Setting public schema for platform admin path: {path}")
            connection.set_schema_to_public()
            return self.get_response(request)
        
        # Extract potential tenant slug from URL path
        path_parts = path.split('/')
        
        # Debug logging
        logger.info(f"Original path: {path}")
        logger.info(f"Original path parts: {path_parts}")
        
        # Handle the new URL pattern: /api/{tenant_slug}/tenant-admin/...
        if (len(path_parts) > 3 and 
            path_parts[1] == 'api' and 
            len(path_parts) > 2 and path_parts[2] and
            len(path_parts) > 3 and (path_parts[3] == 'tenant-admin' or path_parts[3] == 'tenant' or path_parts[3] == 'tenant-admin-roles')):
            
            tenant_slug = path_parts[2]
            logger.info(f"Detected tenant pattern in URL: {path}")
            logger.info(f"Tenant slug from URL: {tenant_slug}")
            
            # Handle [tenant] placeholder in URL
            if tenant_slug == '[tenant]':
                # Check if tenant name is provided in headers
                header_tenant = request.META.get('HTTP_X_TENANT_NAME')
                if header_tenant and header_tenant != '[tenant]':
                    tenant_slug = header_tenant
                    logger.info(f"Using tenant slug from header: {tenant_slug}")
                else:
                    # Try to extract tenant from JWT token
                    from rest_framework_simplejwt.authentication import JWTAuthentication
                    jwt_auth = JWTAuthentication()
                    try:
                        header = jwt_auth.get_header(request)
                        if header:
                            raw_token = jwt_auth.get_raw_token(header)
                            if raw_token:
                                validated_token = jwt_auth.get_validated_token(raw_token)
                                token_tenant_slug = validated_token.get('tenant_slug')
                                if token_tenant_slug:
                                    tenant_slug = token_tenant_slug
                                    logger.info(f"Using tenant slug from JWT token: {tenant_slug}")
                    except Exception as e:
                        logger.warning(f"Error extracting tenant from JWT token: {str(e)}")
            
            # Try to retrieve a Domain with folder matching the tenant_slug
            try:
                # List all domains for debugging
                all_domains = Domain.objects.all()
                logger.info(f"All domains in database: {[f'{d.domain}/{d.folder}' for d in all_domains]}")
                
                domain = Domain.objects.get(folder=tenant_slug)
                tenant = domain.tenant
                logger.info(f"Found tenant via domain folder: {tenant_slug}, tenant: {tenant.schema_name}")
                
                # If a Tenant is found, set the schema_name on the connection
                connection.set_tenant(tenant)
                logger.info(f"Set connection schema to: {connection.schema_name}")
                
                # Set flags and headers for tenant admin context
                request.tenant_url = True
                request.tenant = tenant
                request.tenant_slug = tenant_slug
                if path_parts[3] == 'tenant-admin' or path_parts[3] == 'tenant-admin-roles':
                    request.is_tenant_admin = True
                    request.META['HTTP_X_TENANT_ADMIN'] = 'true'
                request.META['HTTP_X_TENANT_NAME'] = tenant_slug
                
                logger.info(f"Set tenant context for {tenant_slug} with new URL pattern")
                
            except Domain.DoesNotExist:
                logger.warning(f"No domain found with folder='{tenant_slug}'")
                
                # If not found by folder, try the url_suffix
                try:
                    tenant = Tenant.objects.get(url_suffix=tenant_slug)
                    logger.info(f"Found tenant via url_suffix: {tenant_slug}, tenant: {tenant.schema_name}")
                    
                    # If a Tenant is found, set the schema_name on the connection
                    connection.set_tenant(tenant)
                    logger.info(f"Set connection schema to: {connection.schema_name}")
                    
                    # Set flags and headers for tenant admin context
                    request.tenant_url = True
                    request.tenant = tenant
                    request.tenant_slug = tenant_slug
                    if path_parts[3] == 'tenant-admin' or path_parts[3] == 'tenant-admin-roles':
                        request.is_tenant_admin = True
                        request.META['HTTP_X_TENANT_ADMIN'] = 'true'
                    request.META['HTTP_X_TENANT_NAME'] = tenant_slug
                    
                    logger.info(f"Set tenant context for {tenant_slug} with new URL pattern")
                    
                except Tenant.DoesNotExist:
                    logger.warning(f"No tenant found for subfolder \"{tenant_slug}\"")
                    connection.set_schema_to_public()
                    # Continue with the request even if tenant not found
            
            # Keep the path as is, since it's already in the correct format
            logger.info(f"Continuing with original path: {path}")
            response = self.get_response(request)
            logger.info(f"Response status code: {response.status_code}")
            return response
            
        # Handle the problematic pattern: /qa/api/qa/tenant-admin/dashboard/
        if (len(path_parts) > 4 and 
            path_parts[1] and 
            path_parts[2] == 'api' and 
            'tenant-admin' in path_parts):
            
            tenant_slug = path_parts[1]
            logger.debug(f"Detected tenant admin pattern in URL: {path}")
            
            # Find the position of tenant-admin in the path
            tenant_admin_index = path_parts.index('tenant-admin')
            
            # Fix the path to the standard format: /api/{tenant-slug}/tenant-admin/...
            new_path = f'/api/{tenant_slug}/tenant-admin/' + '/'.join(path_parts[tenant_admin_index+1:])
            request.path_info = new_path
            
            logger.debug(f"Fixed path to: {new_path}")
            
            # Try to retrieve a Tenant with url_suffix matching the tenant_slug
            try:
                # First try to find a domain with the folder field matching the tenant_slug
                try:
                    domain = Domain.objects.get(folder=tenant_slug)
                    tenant = domain.tenant
                    logger.debug(f"Found tenant via domain folder: {tenant_slug}")
                except Domain.DoesNotExist:
                    # If not found by folder, try the url_suffix
                    tenant = Tenant.objects.get(url_suffix=tenant_slug)
                    logger.debug(f"Found tenant via url_suffix: {tenant_slug}")
                
                # If a Tenant is found, set the schema_name on the connection
                connection.set_tenant(tenant)
                
                # Set flags and headers for tenant admin context
                request.tenant_url = True
                request.tenant = tenant
                request.tenant_slug = tenant_slug
                request.is_tenant_admin = True
                request.META['HTTP_X_TENANT_ADMIN'] = 'true'
                request.META['HTTP_X_TENANT_NAME'] = tenant_slug
                
                logger.debug(f"Set tenant admin context for {tenant_slug}")
                
                # Continue processing with the modified path
            except (Tenant.DoesNotExist, Domain.DoesNotExist):
                logger.warning(f"Tenant not found for slug: {tenant_slug}")
                connection.set_schema_to_public()
                # Continue with the request even if tenant not found
        
        # Continue with normal processing if not the special case above
        elif len(path_parts) > 1 and path_parts[1]:
            tenant_slug = path_parts[1]
            
            # Skip processing for global API routes
            if tenant_slug == 'api':
                connection.set_schema_to_public()
                return self.get_response(request)
            
            # Try to retrieve a Tenant with url_suffix matching the tenant_slug
            try:
                # First try to find a domain with the folder field matching the tenant_slug
                try:
                    domain = Domain.objects.get(folder=tenant_slug)
                    tenant = domain.tenant
                    logger.debug(f"Found tenant via domain folder: {tenant_slug}")
                except Domain.DoesNotExist:
                    # If not found by folder, try the url_suffix
                    tenant = Tenant.objects.get(url_suffix=tenant_slug)
                    logger.debug(f"Found tenant via url_suffix: {tenant_slug}")
                
                # If a Tenant is found, set the schema_name on the connection
                connection.set_tenant(tenant)
                
                # Set a flag on the request to indicate this is a tenant URL
                request.tenant_url = True
                
                # Store the tenant on the request for later use
                request.tenant = tenant
                request.tenant_slug = tenant_slug
                
                # Check if this is a tenant admin route
                is_tenant_admin = len(path_parts) > 2 and path_parts[2] == 'tenant-admin'
                if is_tenant_admin:
                    request.is_tenant_admin = True
                    # For tenant admin routes, set a header to indicate tenant admin context
                    request.META['HTTP_X_TENANT_ADMIN'] = 'true'
                
                # Log the tenant context for debugging
                logger.debug(f"Set tenant context: {tenant.schema_name} for URL: {path}")
                
                # Add debug logging to show path parts
                logger.debug(f"Path parts: {path_parts}")
                
                # Modify the path to remove the tenant slug
                # For API requests
                if path.startswith(f'/{tenant_slug}/api/'):
                    # Transform /{tenant_slug}/api/... to /api/{tenant_slug}/...
                    new_path = f'/api/{tenant_slug}/' + '/'.join(path_parts[3:])
                    request.path_info = new_path
                    
                    # Check if this is a tenant-admin API route after transformation
                    new_path_parts = new_path.split('/')
                    logger.debug(f"New path parts after transformation: {new_path_parts}")
                    
                    # Check if tenant-admin is in the path (should be at index 3 after transformation)
                    if len(new_path_parts) > 3 and new_path_parts[3] == 'tenant-admin':
                        request.is_tenant_admin = True
                        request.META['HTTP_X_TENANT_ADMIN'] = 'true'
                        request.META['HTTP_X_TENANT_NAME'] = tenant_slug
                        logger.debug(f"Set tenant admin context for API route: {new_path}")
                else:
                    # For frontend routes, keep the path as is
                    # The frontend will handle routing based on the tenant slug
                    pass
                
                # Log the modified path for debugging
                logger.debug(f"Modified path: {request.path_info}")
                
            except (Tenant.DoesNotExist, Domain.DoesNotExist):
                # If no Tenant is found with this url_suffix, do nothing
                # Let Django's normal URL routing handle it (will likely result in a 404)
                logger.debug(f"No tenant found for slug: {tenant_slug}")
                pass
        
        # Call the get_response callable to continue processing the request
        response = self.get_response(request)
        
        # Reset the schema to public after the response is generated
        if hasattr(request, 'tenant_url') and request.tenant_url:
            connection.set_schema_to_public()
            logger.debug(f"Reset schema to public after processing request: {path}")
        
        return response
