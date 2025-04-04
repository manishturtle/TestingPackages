"""
Views for tenant users (not tenant admins).
"""
import logging
from django.db import connection
from django.utils import timezone
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from .models import TenantUser, UserRole, UserProfile

# Configure logging
logger = logging.getLogger(__name__)

class TenantUserCheckView(APIView):
    """
    API endpoint to check if a tenant user exists and has a role.
    
    This view checks if a user exists in the TenantUser table and if they have
    an entry in the UserRole table. It does not require the user to be a tenant admin.
    """
    permission_classes = [AllowAny]
    authentication_classes = []
    
    def post(self, request, *args, **kwargs):
        """
        Check if a tenant user exists and has a role.
        
        Request body:
        - email: string (required)
        
        Returns:
        - 200 OK: {"exists": true, "has_role": true} if the user exists and has a role
        - 200 OK: {"exists": true, "has_role": false} if the user exists but has no role
        - 200 OK: {"exists": false} if the user does not exist
        - 400 Bad Request: If email is not provided
        """
        # Get the email from the request data
        email = request.data.get('email')
        
        # Log the request for debugging
        logger.info(f"TenantUserCheckView - Checking user with email: {email}")
        
        # Check if email is provided
        if not email:
            logger.warning("TenantUserCheckView - No email provided")
            return Response(
                {"detail": "Email is required"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Log the current connection schema
        logger.info(f"TenantUserCheckView - Current connection schema: {connection.schema_name}")
        
        # Check if the user exists in the TenantUser table
        try:
            user = TenantUser.objects.get(email=email)
            logger.info(f"TenantUserCheckView - User found: {user.id}")
            
            # Check if the user has a role
            has_role = UserRole.objects.filter(user=user).exists()
            logger.info(f"TenantUserCheckView - User has role: {has_role}")
            
            return Response({
                "exists": True,
                "has_role": has_role,
                "user_id": user.id,
                "is_active": user.is_active,
                "is_staff": user.is_staff
            })
            
        except TenantUser.DoesNotExist:
            logger.info(f"TenantUserCheckView - User not found with email: {email}")
            return Response({"exists": False})
        except Exception as e:
            logger.error(f"TenantUserCheckView - Error checking user: {str(e)}", exc_info=True)
            return Response(
                {"detail": f"Error checking user: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class TenantUserLoginView(APIView):
    """
    API endpoint for tenant user login.
    
    This view authenticates a tenant user and checks if they have a role.
    It does not require the user to be a tenant admin.
    """
    permission_classes = [AllowAny]
    authentication_classes = []
    
    def post(self, request, *args, **kwargs):
        """
        Authenticate a tenant user.
        
        Request body:
        - email: string (required)
        - password: string (required)
        
        Returns:
        - 200 OK: {"token": "...", "user": {...}} if authentication succeeds
        - 400 Bad Request: If email or password is not provided
        - 401 Unauthorized: If authentication fails
        - 403 Forbidden: If user has no assigned role
        """
        # Get credentials from request data
        email = request.data.get('email')
        password = request.data.get('password')
        
        # Log the request for debugging
        logger.info(f"TenantUserLoginView - Login attempt for user: {email}")
        logger.info(f"TenantUserLoginView - Current connection schema: {connection.schema_name}")
        
        # Validate input
        if not email or not password:
            logger.warning("TenantUserLoginView - Missing email or password")
            return Response(
                {"detail": "Email and password are required"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Manual authentication instead of using Django's authenticate
        try:
            # Find the user by email
            user = TenantUser.objects.get(email=email)
            
            # Check if the password is correct
            if not user.check_password(password):
                logger.warning(f"TenantUserLoginView - Invalid password for: {email}")
                return Response(
                    {"detail": "Invalid credentials"}, 
                    status=status.HTTP_401_UNAUTHORIZED
                )
                
            # Check if the user is active
            if not user.is_active:
                logger.warning(f"TenantUserLoginView - User is inactive: {email}")
                return Response(
                    {"detail": "This account is inactive."}, 
                    status=status.HTTP_401_UNAUTHORIZED
                )
        except TenantUser.DoesNotExist:
            logger.warning(f"TenantUserLoginView - User not found: {email}")
            return Response(
                {"detail": "Invalid credentials"}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Check if user has a role
        has_role = UserRole.objects.filter(user=user).exists()
        
        if not has_role:
            logger.warning(f"TenantUserLoginView - User has no role: {email}")
            return Response(
                {"detail": "Your account does not have any assigned roles. Please contact your administrator."}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Get user profile
        try:
            profile = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist:
            logger.error(f"TenantUserLoginView - No profile found for user: {user.id}")
            return Response(
                {"detail": "User profile not found"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        # Generate JWT token
        refresh = RefreshToken.for_user(user)
        
        # Add custom claims to the token
        refresh['email'] = user.email
        refresh['user_id'] = user.id
        refresh['is_staff'] = user.is_staff
        refresh['is_tenant_admin'] = profile.is_tenant_admin
        
        # Add tenant information
        if hasattr(request, 'tenant'):
            refresh['tenant_id'] = request.tenant.id
            refresh['tenant_schema'] = request.tenant.schema_name
            refresh['tenant_slug'] = request.tenant_slug
        
        # Update last login
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])
        
        # Log successful login
        logger.info(f"TenantUserLoginView - Login successful for user: {user.id}")
        
        # Return token and user data
        return Response({
            "token": {
                "access": str(refresh.access_token),
                "refresh": str(refresh)
            },
            "user": {
                "id": user.id,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "is_staff": user.is_staff,
                "is_tenant_admin": profile.is_tenant_admin,
                "has_role": has_role
            }
        })
