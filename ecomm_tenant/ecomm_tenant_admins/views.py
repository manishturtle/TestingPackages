from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from rest_framework.response import Response
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authentication import TokenAuthentication
from django.utils import timezone
from ecomm_superadmin.models import User, Tenant, Domain
from ecomm_tenant.ecomm_tenant_admins.models import (
    TenantUser, UserProfile, PendingRegistration, 
    Role, Permission, RolePermission, UserRole, OTP,
    Company
)
from .serializers import (
    UserSerializer, CompanySerializer, UserProfileSerializer,
    RegistrationSerializer, LoginSerializer, PasswordResetSerializer,
    PasswordResetConfirmSerializer, ChangePasswordSerializer,
    EmailCheckSerializer, OTPVerificationSerializer, TenantSerializer,
    SubscriptionPlanSerializer, PermissionSerializer, RoleSerializer,
    UserRoleSerializer, UserRegistrationSerializer, PendingRegistrationSerializer,
    TwoFactorLoginResponseSerializer, TwoFactorVerifyRequestSerializer,
    TenantUserCreateSerializer, TenantUserDisplaySerializer
)
import os
import json
import requests
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse
from rest_framework.authtoken.models import Token
from rest_framework_simplejwt.tokens import RefreshToken
from .utils import generate_2fa_secret, generate_otp, send_otp_email, generate_temp_token
from rest_framework import viewsets, permissions
from django.db import connection
from django.db import transaction
from django.conf import settings
from tenant_schemas.utils import tenant_context
import re
import random
import string
import logging
from .permissions import IsTenantAdmin, HasTenantPermission, IsCurrentTenantAdmin
import secrets
from .tasks import send_new_tenant_user_welcome_email

# Get the logger
logger = logging.getLogger(__name__)

# Note: 2FA with TOTP is available using generate_2fa_secret() from utils.py

class CheckEmailView(APIView):
    """
    API endpoint to check if an email is available for registration.
    
    This endpoint is only available in tenant context, not in platform-admin.
    """
    permission_classes = [AllowAny]
    authentication_classes = []
    
    def post(self, request, *args, **kwargs):
        """
        Check if the email is already registered.
        
        Request body:
        - email: string (required)
        
        Returns:
        - 200 OK: {"email_available": true} if email is available
        - 409 Conflict: {"email_available": false, "message": "Email already registered"} if email is taken
        - 400 Bad Request: Validation errors if request data is invalid
        - 403 Forbidden: If accessed from platform-admin context
        """
        # Check if we're in platform-admin context (not tenant context)
        if not hasattr(request, 'tenant_url') or not request.tenant_url:
            return Response(
                {"detail": "Registration is not allowed in platform-admin context"},
                status=status.HTTP_403_FORBIDDEN
            )
            
        email = request.data.get('email')
        
        if not email:
            return Response(
                {"email": ["This field is required."]},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if a user with this email already exists
        email_exists = User.objects.filter(email__iexact=email).exists()
        username_exists = User.objects.filter(username__iexact=email).exists()
        
        if email_exists or username_exists:
            return Response(
                {
                    "email_available": False,
                    "message": "Email already registered"
                },
                status=status.HTTP_409_CONFLICT
            )
        
        return Response({"email_available": True}, status=status.HTTP_200_OK)

class CheckUserExistsView(APIView):
    """
    API endpoint to check if a user exists for login.
    
    This view works in tenant, tenant admin, and platform admin contexts.
    """
    permission_classes = [AllowAny]
    authentication_classes = []
    
    def post(self, request, *args, **kwargs):
        """
        Check if the user exists.
        
        Request body:
        - email: string (required)
        
        Headers:
        - X-Platform-Admin: 'true' (optional) - Flag to indicate platform admin user check
        - X-Tenant-Admin: 'true' (optional) - Flag to indicate tenant admin user check
        - X-Tenant-Name: string (optional) - Tenant name for tenant admin context
        
        Returns:
        - 200 OK: {"user_exists": true} if user exists
        - 404 Not Found: {"user_exists": false, "message": "User does not exist"} if user does not exist
        - 400 Bad Request: Validation errors if request data is invalid
        """
        email = request.data.get('email')
        is_platform_admin = request.headers.get('X-Platform-Admin') == 'true'
        is_tenant_admin = request.headers.get('X-Tenant-Admin') == 'true'
        tenant_name = request.headers.get('X-Tenant-Name')
        
        # Add debugging information
        logger.info(f"CheckUserExistsView - Request data: {request.data}")
        logger.info(f"CheckUserExistsView - Headers: {request.headers}")
        logger.info(f"CheckUserExistsView - Email: {email}")
        logger.info(f"CheckUserExistsView - Is platform admin: {is_platform_admin}")
        logger.info(f"CheckUserExistsView - Is tenant admin: {is_tenant_admin}")
        logger.info(f"CheckUserExistsView - Tenant name: {tenant_name}")
        
        # If this is a tenant-specific request, log the current schema
        if hasattr(request, 'tenant'):
            logger.info(f"CheckUserExistsView - Current tenant: {request.tenant.schema_name}")
        else:
            logger.info("CheckUserExistsView - No tenant in request")
        
        # Log the current connection schema
        logger.info(f"CheckUserExistsView - Current connection schema: {connection.schema_name}")
        
        # Check if we need to set the tenant schema manually
        # This is needed for API routes that don't go through the middleware's tenant detection
        if is_tenant_admin and tenant_name and connection.schema_name == 'public':
            try:
                # First try to find by folder in Domain model
                try:
                    domain = Domain.objects.get(folder=tenant_name)
                    tenant_client = domain.tenant
                    logger.info(f"CheckUserExistsView - Found tenant via domain folder: {tenant_name}")
                except Domain.DoesNotExist:
                    # If not found by folder, try the url_suffix
                    tenant_client = Tenant.objects.get(url_suffix=tenant_name)
                    logger.info(f"CheckUserExistsView - Found tenant via url_suffix: {tenant_name}")
                
                logger.info(f"CheckUserExistsView - Manually setting schema to: {tenant_client.schema_name}")
                connection.set_tenant(tenant_client)
                
                # Store tenant info on request for consistency
                request.tenant = tenant_client
                request.tenant_slug = tenant_name
                request.tenant_url = True
                request.is_tenant_admin = True
            except (Tenant.DoesNotExist, Domain.DoesNotExist):
                logger.warning(f"CheckUserExistsView - Tenant not found: {tenant_name}")
                return Response(
                    {
                        "user_exists": False,
                        "message": f"Tenant '{tenant_name}' does not exist"
                    },
                    status=status.HTTP_404_NOT_FOUND
                )
        
        if not email:
            return Response(
                {"email": ["This field is required."]},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if a user with this email exists
        try:
            logger.info(f"CheckUserExistsView - Looking for user with email: {email} in schema: {connection.schema_name}")
            
            # For platform admin, check in the public schema User model
            if is_platform_admin:
                try:
                    user = User.objects.get(email__iexact=email)
                    logger.info(f"CheckUserExistsView - Platform admin user found: {user.id} - {user.email}")
                    
                    # Verify the user is staff
                    if not user.is_staff:
                        logger.warning(f"CheckUserExistsView - User {user.email} is not a platform admin")
                        return Response(
                            {
                                "user_exists": False,
                                "message": "User is not a platform administrator"
                            },
                            status=status.HTTP_404_NOT_FOUND
                        )
                    
                    logger.info(f"CheckUserExistsView - Platform admin user check successful for: {user.email}")
                    return Response({"user_exists": True}, status=status.HTTP_200_OK)
                    
                except User.DoesNotExist:
                    logger.warning(f"CheckUserExistsView - Platform admin user not found with email: {email}")
                    return Response(
                        {
                            "user_exists": False,
                            "message": "User does not exist"
                        },
                        status=status.HTTP_404_NOT_FOUND
                    )
            
            # For tenant admin or regular tenant users, check in the tenant schema TenantUser model
            else:
                try:
                    # Use TenantUser model for tenant schemas
                    tenant_user = TenantUser.objects.get(email__iexact=email)
                    logger.info(f"CheckUserExistsView - Tenant user found: {tenant_user.id} - {tenant_user.email}")
                    
                    # If tenant admin check, verify the user is a tenant admin
                    if is_tenant_admin:
                        try:
                            # Get the user profile
                            profile = UserProfile.objects.get(user=tenant_user)
                            logger.info(f"CheckUserExistsView - User profile found: {profile.id}")
                            
                            # Check if user has tenant admin role
                            if not profile.is_tenant_admin:
                                logger.warning(f"CheckUserExistsView - User {tenant_user.email} is not a tenant admin")
                                return Response(
                                    {
                                        "user_exists": False,
                                        "message": "User is not a tenant administrator"
                                    },
                                    status=status.HTTP_404_NOT_FOUND
                                )
                            
                            # For tenant admin context, we don't need to check company association
                            # Just verify the user is a tenant admin in this tenant schema
                            logger.info(f"CheckUserExistsView - User {tenant_user.email} is a tenant admin in schema: {connection.schema_name}")
                            return Response({"user_exists": True}, status=status.HTTP_200_OK)
                            
                        except UserProfile.DoesNotExist:
                            logger.warning(f"CheckUserExistsView - User profile not found for user: {tenant_user.email}")
                            return Response(
                                {
                                    "user_exists": False,
                                    "message": "User profile not found"
                                },
                                status=status.HTTP_404_NOT_FOUND
                            )
                    
                    # If in tenant context, verify the user belongs to this tenant
                    elif hasattr(request, 'tenant_url') and request.tenant_url:
                        try:
                            profile = UserProfile.objects.get(user=tenant_user)
                            logger.info(f"CheckUserExistsView - User profile found: {profile.id}")
                            
                            if not profile.company or (hasattr(profile.company, 'tenant') and profile.company.tenant != request.tenant):
                                logger.warning(f"CheckUserExistsView - User {tenant_user.email} does not belong to tenant {request.tenant.schema_name}")
                                return Response(
                                    {
                                        "user_exists": False,
                                        "message": "User does not exist in this tenant"
                                    },
                                    status=status.HTTP_404_NOT_FOUND
                                )
                        except UserProfile.DoesNotExist:
                            logger.warning(f"CheckUserExistsView - User profile not found for user: {tenant_user.email}")
                            return Response(
                                {
                                    "user_exists": False,
                                    "message": "User profile not found"
                                },
                                status=status.HTTP_404_NOT_FOUND
                            )
                    
                    logger.info(f"CheckUserExistsView - User check successful for: {tenant_user.email}")
                    return Response({"user_exists": True}, status=status.HTTP_200_OK)
                    
                except TenantUser.DoesNotExist:
                    logger.warning(f"CheckUserExistsView - Tenant user not found with email: {email}")
                    return Response(
                        {
                            "user_exists": False,
                            "message": "User does not exist"
                        },
                        status=status.HTTP_404_NOT_FOUND
                    )
            
        except Exception as e:
            logger.error(f"CheckUserExistsView - Unexpected error: {str(e)}")
            return Response(
                {
                    "user_exists": False,
                    "message": f"Error checking user: {str(e)}"
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class RegisterUserView(APIView):
    """
    API endpoint for user registration.
    
    This endpoint is only available in tenant context, not in platform-admin.
    """
    permission_classes = [AllowAny]
    authentication_classes = []
    
    def post(self, request, *args, **kwargs):
        """
        Start the registration process by creating a pending registration.
        
        Request body:
        - email: string (required)
        - password: string (required)
        - password_confirm: string (required)
        - first_name: string (required)
        - last_name: string (required)
        - nationality: string (required)
        
        Returns:
        - 201 Created: Pending registration data if validation is successful
        - 400 Bad Request: Validation errors if request data is invalid
        - 403 Forbidden: If accessed from platform-admin context
        """
        # Check if we're in platform-admin context (not tenant context)
        if not hasattr(request, 'tenant_url') or not request.tenant_url:
            return Response(
                {"detail": "Registration is not allowed in platform-admin context"},
                status=status.HTTP_403_FORBIDDEN
            )
            
        print(f"Registration request data: {request.data}")
        
        serializer = PendingRegistrationSerializer(data=request.data)
        
        if not serializer.is_valid():
            print(f"Validation errors: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        print(f"Validated data: {serializer.validated_data}")
        
        # Check if a user with this email already exists
        email = serializer.validated_data.get('email')
        if User.objects.filter(username=email).exists():
            return Response(
                {"message": "A user with this email already exists. Please use a different email."},
                status=status.HTTP_409_CONFLICT
            )
        
        try:
            # Save the pending registration using the serializer
            pending_reg = serializer.save()
            
            # Generate OTP
            otp = generate_otp()
            pending_reg.otp = otp
            pending_reg.save()
            
            # Send OTP email
            send_otp_email(pending_reg.email, pending_reg.first_name, otp)
            
            return Response({
                'id': pending_reg.id,
                'email': pending_reg.email,
                'first_name': pending_reg.first_name,
                'last_name': pending_reg.last_name
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            print(f"Error creating pending registration: {str(e)}")
            return Response(
                {"message": f"Error creating registration: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class VerifyOtpView(APIView):
    """
    API endpoint for verifying OTP during registration.
    
    This endpoint is only available in tenant context, not in platform-admin.
    """
    permission_classes = [AllowAny]
    authentication_classes = []
    
    def post(self, request, *args, **kwargs):
        """
        Verify the OTP and create the user if valid.
        
        Request body:
        - email: string (required)
        - user_id: integer (required) - ID of the pending registration
        - otp: string (required)
        
        Returns:
        - 200 OK: {"verified": True, "user": user_data} if OTP is valid
        - 400 Bad Request: {"verified": false, "message": "Invalid OTP"} if OTP is invalid
        - 403 Forbidden: If accessed from platform-admin context
        """
        # Check if we're in platform-admin context (not tenant context)
        if not hasattr(request, 'tenant_url') or not request.tenant_url:
            return Response(
                {"detail": "Registration is not allowed in platform-admin context"},
                status=status.HTTP_403_FORBIDDEN
            )
            
        print(f"OTP verification request data: {request.data}")
        
        email = request.data.get('email')
        user_id = request.data.get('user_id')
        otp = request.data.get('otp')
        
        if not all([email, user_id, otp]):
            print("Missing required fields")
            return Response(
                {"message": "Email, user_id, and OTP are required."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Get the pending registration
            pending_reg = PendingRegistration.objects.get(id=user_id, email=email)
            print(f"Found pending registration: {pending_reg.id}, OTP: {pending_reg.otp}, Input OTP: {otp}")
            
            if pending_reg.otp == otp:
                print("OTP verified successfully")
                
                # Check if a user with this email already exists
                existing_user = User.objects.filter(username=pending_reg.email).first()
                if existing_user:
                    # Return error message
                    return Response(
                        {"message": "A user with this email already exists. Please use a different email."},
                        status=status.HTTP_409_CONFLICT
                    )
                
                # Create the actual user
                user = User.objects.create_user(
                    username=pending_reg.email,
                    email=pending_reg.email,
                    first_name=pending_reg.first_name,
                    last_name=pending_reg.last_name,
                    password=pending_reg.password  # create_user will hash the password
                )
                
                # Ensure the user is saved and committed to the database
                user.save()
                
                # Create company for this tenant if it doesn't exist
                company_name = pending_reg.company_name
                company, created = Company.objects.get_or_create(
                    name=company_name,
                    defaults={'tenant': request.tenant}  # Include tenant in defaults
                )
                
                # Associate the company with the tenant
                # company.tenant = request.tenant  # Not needed since we included tenant in defaults
                # company.save()
                
                # Create user profile
                profile = UserProfile.objects.create(
                    user=user,
                    company=company,  # Associate with the company
                    nationality=pending_reg.nationality,
                    is_company_admin=True,
                    is_tenant_admin=True,
                    is_email_verified=True,
                    needs_2fa_setup=True  # Mark that user needs to set up 2FA
                )
                
                # Ensure the profile is saved
                profile.save()
                
                # Delete the pending registration
                pending_reg.delete()
                
                # Return user data
                profile_serializer = UserProfileSerializer(profile)
                
                response_data = {
                    "verified": True,
                    "user": profile_serializer.data,
                    "message": "Email verified successfully! Your account has been created.",
                    "needs_2fa_setup": True,  # Add flag to indicate 2FA setup is required
                    "user_id": user.id,  # Include user ID for 2FA setup
                    "temp_token": generate_temp_token(user)  # Generate temporary token for 2FA setup
                }
                print(f"Sending response: {response_data}")
                
                return Response(response_data, status=status.HTTP_200_OK)
            else:
                print(f"Invalid OTP: {otp} != {pending_reg.otp}")
                return Response(
                    {"verified": False, "message": "Invalid OTP. Please try again."},
                    status=status.HTTP_400_BAD_REQUEST
                )
        except PendingRegistration.DoesNotExist:
            print(f"Pending registration not found: {user_id}, {email}")
            return Response(
                {"message": "Registration not found or expired."},
                status=status.HTTP_404_NOT_FOUND
            )

class ResendOtpView(APIView):
    """
    API endpoint for resending OTP during registration.
    
    This endpoint is only available in tenant context, not in platform-admin.
    """
    permission_classes = [AllowAny]
    
    def post(self, request, *args, **kwargs):
        """
        Resend OTP to the user's email.
        
        Request body:
        - email: string (required)
        - user_id: integer (required) - ID of the pending registration
        
        Returns:
        - 200 OK: {"sent": true} if OTP is sent successfully
        - 400 Bad Request: Validation errors if request data is invalid
        - 403 Forbidden: If accessed from platform-admin context
        """
        # Check if we're in platform-admin context (not tenant context)
        if not hasattr(request, 'tenant_url') or not request.tenant_url:
            return Response(
                {"detail": "Registration is not allowed in platform-admin context"},
                status=status.HTTP_403_FORBIDDEN
            )
            
        email = request.data.get('email')
        user_id = request.data.get('user_id')
        
        if not all([email, user_id]):
            return Response(
                {"message": "Email and user_id are required."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            pending_reg = PendingRegistration.objects.get(id=user_id, email=email)
            
            # Generate new OTP
            otp = generate_otp()
            pending_reg.otp = otp
            pending_reg.save()
            
            # Send OTP email
            send_otp_email(pending_reg.email, pending_reg.first_name, otp)
            
            return Response({"sent": True}, status=status.HTTP_200_OK)
        except PendingRegistration.DoesNotExist:
            return Response(
                {"message": "Registration not found or expired."},
                status=status.HTTP_404_NOT_FOUND
            )

class UserProfileView(APIView):
    """
    API endpoint for retrieving user profile information.
    """
    
    def get(self, request, *args, **kwargs):
        """
        Get the profile of the authenticated user.
        
        Returns:
        - 200 OK: User profile data
        - 401 Unauthorized: If user is not authenticated
        """
        if not request.user.is_authenticated:
            return Response({"detail": "Authentication required"}, status=status.HTTP_401_UNAUTHORIZED)
        
        try:
            profile = UserProfile.objects.get(user=request.user)
            serializer = UserProfileSerializer(profile)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except UserProfile.DoesNotExist:
            return Response({"detail": "Profile not found"}, status=status.HTTP_404_NOT_FOUND)

class LoginView(APIView):
    """
    API endpoint for user login.
    
    This view handles authentication in tenant, tenant admin, and platform admin contexts:
    - In tenant context (request.tenant_url=True): Only allows users associated with the current tenant
    - In tenant admin context: Only allows users with tenant admin role for the specified tenant
    - In platform admin context: Only allows staff members to login
    """
    permission_classes = [AllowAny]
    authentication_classes = []
    
    def post(self, request, *args, **kwargs):
        """
        Authenticate a user.
        
        Request body:
        - email: string (required)
        - password: string (required)
        
        Headers:
        - X-Platform-Admin: 'true' (optional) - Flag to indicate platform admin login attempt
        - X-Tenant-Admin: 'true' (optional) - Flag to indicate tenant admin login attempt
        - X-Tenant-Name: string (optional) - Tenant name for tenant admin context
        
        Returns:
        - 202 Accepted: {"requires_2fa": true, "user_id": user_id} if 2FA is required
        - 202 Accepted: {"needs_2fa_setup": true, "user_id": user_id, "temp_token": temp_token} if 2FA setup is required
        - 401 Unauthorized: If credentials are invalid
        - 403 Forbidden: If user is not allowed to access this tenant or not a staff member in platform admin context
        """
        # Handle potential nested payload structure
        request_data = request.data
        
        # Check if email is nested (e.g., {email: {email: "actual@email.com", password: "pwd"}, password: "tenant"})
        if isinstance(request_data.get('email'), dict) and 'email' in request_data.get('email'):
            nested_data = request_data.get('email')
            email = nested_data.get('email')
            password = nested_data.get('password')
        else:
            # Regular structure
            email = request_data.get('email')
            password = request_data.get('password')
        
        # Debug logging
        print(f"DEBUG: Request data: {request_data}")
        print(f"DEBUG: Extracted email: {email}, password: {'*' * len(password) if password else None}")
        
        # Check for context headers
        is_platform_admin = request.headers.get('X-Platform-Admin') == 'true'
        is_tenant_admin = request.headers.get('X-Tenant-Admin') == 'true'
        tenant_name = request.headers.get('X-Tenant-Name')
        
        if not email or not password:
            return Response(
                {"detail": "Email and password are required"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # If tenant name is provided in the header or we're in a tenant context,
        # we need to find the tenant and set the schema
        tenant = None
        original_schema = None
        
        # Check if we're in a tenant context from the middleware
        if hasattr(request, 'tenant') and request.tenant:
            tenant = request.tenant
        # Or if tenant name is provided in the header
        elif tenant_name:
            try:
                tenant = Tenant.objects.get(url_suffix=tenant_name)
            except Tenant.DoesNotExist:
                return Response(
                    {"detail": f"Tenant '{tenant_name}' does not exist"}, 
                    status=status.HTTP_404_NOT_FOUND
                )
        
        # If we have a tenant, switch to its schema for user lookup
        if tenant and not is_platform_admin:
            print(f"DEBUG: Found tenant: {tenant.schema_name}, current schema: {connection.schema_name}")
            print(f"DEBUG: Tenant details - Name: {tenant.name}, URL Suffix: {tenant.url_suffix}")
            
            # Store original schema before switching
            original_schema = connection.schema_name
            print(f"DEBUG: Original schema stored as: {original_schema}")
            
            try:
                # Try to set tenant schema
                connection.set_tenant(tenant)
                print(f"DEBUG: After set_tenant, schema is now: {connection.schema_name}")
                
                # Verify if schema was actually changed
                if connection.schema_name == tenant.schema_name:
                    print(f"DEBUG: Schema successfully changed to: {connection.schema_name}")
                else:
                    print(f"DEBUG: WARNING! Schema not changed. Expected: {tenant.schema_name}, Got: {connection.schema_name}")
            except Exception as e:
                print(f"DEBUG: Error setting tenant schema: {str(e)}")
        
        try:
            # Find the user by email in the current schema (which might be a tenant schema)
            try:
                # Use the correct user model based on the context
                if is_platform_admin:
                    # For platform admin, use the User model from the public schema
                    user = User.objects.get(email__iexact=email)
                else:
                    # For tenant context, use the TenantUser model
                    from ecomm_tenant.ecomm_tenant_admins.models import TenantUser
                    user = TenantUser.objects.get(email__iexact=email)
            except (User.DoesNotExist, TenantUser.DoesNotExist):
                # Reset schema if we changed it
                if original_schema:
                    connection.set_schema_to_public()
                
                return Response(
                    {"detail": "Invalid email or password"}, 
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            # Check the password
            if not user.check_password(password):
                # Reset schema if we changed it
                if original_schema:
                    connection.set_schema_to_public()
                
                return Response(
                    {"detail": "Invalid email or password"}, 
                    status=status.HTTP_401_UNAUTHORIZED
                )
            
            # If platform admin login is requested, check if user is staff
            if is_platform_admin:
                if not user.is_staff:
                    return Response(
                        {"detail": "Only staff members can access the platform admin"}, 
                        status=status.HTTP_403_FORBIDDEN
                    )
                    
                # For platform admins, we don't need to check for a profile
                # Create a token for the user
                token, created = Token.objects.get_or_create(user=user)
                
                # Check if 2FA is enabled for this user
                try:
                    profile = UserProfile.objects.get(user=user)
                    if profile.is_2fa_enabled:
                        return Response({
                            "requires_2fa": True,
                            "user_id": user.id
                        }, status=status.HTTP_202_ACCEPTED)
                    
                    if profile.needs_2fa_setup:
                        # Generate a temporary token for 2FA setup
                        temp_token = generate_temp_token(user)
                        
                        # Store the token with the user
                        profile.temp_token = temp_token
                        profile.save()
                        
                        return Response({
                            "needs_2fa_setup": True,
                            "user_id": user.id,
                            "temp_token": temp_token
                        }, status=status.HTTP_202_ACCEPTED)
                except UserProfile.DoesNotExist:
                    # Create a profile for the platform admin if it doesn't exist
                    profile = UserProfile.objects.create(
                        user=user,
                        is_email_verified=True,
                        is_2fa_enabled=False,
                        needs_2fa_setup=False
                    )
                
                # Return the token and user data
                return Response({
                    "token": token.key,
                    "user": {
                        "id": user.id,
                        "email": user.email,
                        "first_name": user.first_name,
                        "last_name": user.last_name,
                        "is_staff": user.is_staff,
                        "is_active": user.is_active
                    }
                }, status=status.HTTP_200_OK)
            # If tenant admin login is requested, check if user is a tenant admin
            elif is_tenant_admin:
                try:
                    profile = UserProfile.objects.get(user=user)
                    
                    # Check if user has tenant admin role
                    if not profile.is_tenant_admin:
                        return Response(
                            {"detail": "You don't have tenant administrator privileges"}, 
                            status=status.HTTP_403_FORBIDDEN
                        )
                    
                    # If tenant name is provided, check if user belongs to that tenant
                    if tenant:
                        # For tenant admin users, we don't need to check company association
                        # Just verify the user is a tenant admin in this tenant schema
                        tenant_info = {
                            'id': tenant.id,
                            'name': tenant.name,
                            'url_suffix': tenant.url_suffix,
                            'status': tenant.status
                        }
                except UserProfile.DoesNotExist:
                    return Response(
                        {"detail": "Profile not found"}, 
                        status=status.HTTP_404_NOT_FOUND
                    )
            # Otherwise, check tenant context
            elif tenant:
                # We're in a tenant context, ensure user belongs to this tenant
                try:
                    profile = UserProfile.objects.get(user=user)
                    
                    # Check if user's company belongs to this tenant
                    if not profile.company or profile.company.tenant != tenant:
                        return Response(
                            {"detail": "You don't have access to this tenant"}, 
                            status=status.HTTP_403_FORBIDDEN
                        )
                except UserProfile.DoesNotExist:
                    return Response(
                        {"detail": "Profile not found"}, 
                        status=status.HTTP_404_NOT_FOUND
                    )
            else:
                # We're in platform admin context, ensure user is staff
                if not user.is_staff:
                    return Response(
                        {"detail": "Only staff members can access the platform admin"}, 
                        status=status.HTTP_403_FORBIDDEN
                    )
            
            # Get the user profile
            try:
                profile = UserProfile.objects.get(user=user)
                
                # Check if 2FA is enabled for this user
                if profile.is_2fa_enabled:
                    # Return a partial login response indicating 2FA is required
                    response_data = {
                        'requires_2fa': True,
                        'user_id': user.id,
                        'message': 'Two-factor authentication required'
                    }
                    
                    # Add tenant info for tenant admin
                    if tenant:
                        response_data['tenant'] = {
                            'id': tenant.id,
                            'name': tenant.name,
                            'url_suffix': tenant.url_suffix,
                            'schema_name': tenant.schema_name,
                            'status': tenant.status
                        }
                    
                    return Response(response_data, status=status.HTTP_202_ACCEPTED)
                
                # For tenant admins, use JWT tokens with additional claims
                refresh = RefreshToken.for_user(user)
                
                # Add custom claims to the token
                refresh['is_tenant_admin'] = profile.is_tenant_admin and user.is_staff
                refresh['is_staff'] = user.is_staff
                
                # Log the token claims for debugging
                print(f"DEBUG: Token claims - is_tenant_admin: {profile.is_tenant_admin and user.is_staff}, is_staff: {user.is_staff}")
                
                # Add tenant info to the token if available
                if tenant:
                    refresh['tenant_id'] = tenant.id
                    refresh['tenant_schema'] = tenant.schema_name
                    refresh['tenant_slug'] = tenant.url_suffix
                    print(f"DEBUG: Token tenant info - ID: {tenant.id}, Schema: {tenant.schema_name}, Slug: {tenant.url_suffix}")
                
                # Prepare the response data with JWT tokens
                response_data = {
                    'token': {
                        'access': str(refresh.access_token),
                        'refresh': str(refresh)
                    },
                    'user_id': user.id,
                    'user': {
                        'id': user.id,
                        'email': user.email,
                        'first_name': user.first_name,
                        'last_name': user.last_name,
                        'is_staff': user.is_staff,
                        'is_active': user.is_active,
                        'is_tenant_admin': profile.is_tenant_admin,
                        'is_company_admin': profile.is_company_admin
                    },
                    'message': 'Login successful'
                }
                
                print(f"DEBUG: Sending response data: {response_data}")
                return Response(response_data, status=status.HTTP_200_OK)
            except UserProfile.DoesNotExist:
                return Response(
                    {"detail": "Profile not found"}, 
                    status=status.HTTP_404_NOT_FOUND
                )
        finally:
            # Always reset the schema to public if we changed it
            if original_schema:
                connection.set_schema_to_public()

class SignupVerifyAndCompleteView(APIView):
    """
    API endpoint for verifying 2FA during signup and completing the registration process.
    """
    permission_classes = [AllowAny]
    authentication_classes = []
    
    def post(self, request, *args, **kwargs):
        """
        Verify the 2FA code and complete the signup process.
        
        Request body:
        - email: string (required)
        - verification_code: string (required) - 6-digit TOTP code
        - user_id: integer (required) - ID of the user
        - backup_secret: string (required) - Backup secret for 2FA
        
        Returns:
        - 200 OK: {"success": true, "message": "Signup completed successfully", "token": {...}} if successful
        - 400 Bad Request: {"success": false, "message": "Invalid verification code"} if verification fails
        """
        # Get request data
        email = request.data.get('email')
        verification_code = request.data.get('verification_code')
        user_id = request.data.get('user_id')
        backup_secret = request.data.get('backup_secret')
        
        # Validate input
        if not email or not verification_code or not user_id:
            return Response(
                {
                    "success": False,
                    "message": "Email, verification code, and user ID are required"
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validate verification code format
        if not verification_code.isdigit() or len(verification_code) != 6:
            return Response(
                {
                    "success": False,
                    "message": "Verification code must be a 6-digit number"
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get the user
        try:
            user = User.objects.get(id=user_id, email=email)
        except User.DoesNotExist:
            return Response(
                {
                    "success": False,
                    "message": "User not found"
                },
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Get the user profile
        try:
            user_profile = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist:
            return Response(
                {
                    "success": False,
                    "message": "User profile not found"
                },
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check if 2FA is enabled
        if not user_profile.is_2fa_enabled:
            return Response(
                {
                    "success": False,
                    "message": "Two-factor authentication is not enabled for this user"
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Verify the 2FA code
        try:
            # Decrypt the secret
            if not user_profile.totp_secret:
                return Response(
                    {
                        "success": False,
                        "message": "No 2FA secret found for this user"
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Try to fix the TOTP secret if needed
            fixed = check_and_fix_totp_secret(user_profile)
            if fixed:
                user_profile.refresh_from_db()
            
            try:
                secret = decrypt_secret(user_profile.totp_secret)
            except Exception as e:
                print(f"Error decrypting TOTP secret: {str(e)}")
                
                # If we can't decrypt the secret and a backup secret was provided, use it
                if backup_secret:
                    print(f"Using provided backup secret")
                    secret = backup_secret
                else:
                    # If no backup secret, generate a new one
                    secret = generate_2fa_secret()
                    user_profile.totp_secret = encrypt_secret(secret)
                    user_profile.save()
                    print(f"Generated new TOTP secret: {secret}")
            
            # Verify the code
            if not verify_2fa_code(secret, verification_code):
                # If verification fails with the decrypted secret and a backup secret was provided,
                # try verifying with the backup secret
                if backup_secret and secret != backup_secret:
                    print(f"Trying verification with backup secret")
                    if verify_2fa_code(backup_secret, verification_code):
                        print(f"Verification succeeded with backup secret")
                        # Update the user's secret to the backup secret
                        user_profile.totp_secret = encrypt_secret(backup_secret)
                        user_profile.save()
                    else:
                        return Response(
                            {
                                "success": False,
                                "message": "Invalid verification code"
                            },
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    return Response(
                        {
                            "success": False,
                            "message": "Invalid verification code"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )
        except Exception as e:
            return Response(
                {
                    "success": False,
                    "message": f"Error verifying 2FA code: {str(e)}"
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        # Generate authentication tokens
        from rest_framework_simplejwt.tokens import RefreshToken
        refresh = RefreshToken.for_user(user)
        token = {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }
        
        # Get the user data
        user_data = {
            'id': user.id,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'is_2fa_enabled': user_profile.is_2fa_enabled,
            'needs_2fa_setup': user_profile.needs_2fa_setup
        }
        
        # Return success response with token
        return Response(
            {
                "success": True,
                "message": "Signup completed successfully",
                "token": token,
                "user": user_data
            },
            status=status.HTTP_200_OK
        )

class TenantAdminVerifyView(APIView):
    """
    API endpoint for verifying 2FA during tenant admin login.
    """
    permission_classes = [AllowAny]
    authentication_classes = []
    
    def post(self, request, *args, **kwargs):
        """
        Verify the 2FA code and complete the tenant admin login process.
        
        Request body:
        - user_id: integer (required) - ID of the user
        - code: string (required) - 6-digit TOTP code
        - tenant_name: string (required) - Name of the tenant
        
        Returns:
        - 200 OK: {"success": true, "message": "Login successful", "token": {...}} if successful
        - 400 Bad Request: {"success": false, "message": "Invalid verification code"} if verification fails
        """
        serializer = TwoFactorVerifyRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        user_id = serializer.validated_data['user_id']
        code = serializer.validated_data['code']
        tenant_name = request.data.get('tenant_name')
        
        if not tenant_name:
            return Response(
                {"detail": "Tenant name is required"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {"detail": "User not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        try:
            profile = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist:
            return Response(
                {"detail": "User profile not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Verify the user is a tenant admin
        if not profile.is_tenant_admin:
            return Response(
                {"detail": "User is not a tenant administrator"}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Verify the tenant exists
        try:
            tenant = Tenant.objects.get(url_suffix=tenant_name)
        except Tenant.DoesNotExist:
            return Response(
                {"detail": f"Tenant '{tenant_name}' does not exist"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Verify the user belongs to this tenant
        if not profile.company or profile.company.tenant != tenant:
            return Response(
                {"detail": f"User is not an administrator for tenant '{tenant_name}'"}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Verify the 2FA code
        import pyotp
        totp = pyotp.TOTP(profile.totp_secret)
        
        if not totp.verify(code):
            return Response(
                {"success": False, "message": "Invalid verification code"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Generate token
        token, created = Token.objects.get_or_create(user=user)
        
        # Create tenant info for response
        tenant_info = {
            'id': tenant.id,
            'name': tenant.name,
            'url_suffix': tenant.url_suffix,
            'status': tenant.status
        }
        
        # Return success response with token and tenant info
        return Response({
            "success": True,
            "message": "Login successful",
            "token": token.key,
            "user": {
                "id": user.id,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "is_tenant_admin": profile.is_tenant_admin
            },
            "tenant_info": tenant_info
        }, status=status.HTTP_200_OK)

class TenantAdminVerifyOTPView(APIView):
    """
    API endpoint for tenant admins to verify the OTP sent to their email.
    
    This view handles the second step of the forgot password flow:
    1. Validates the email and OTP
    2. Checks if the OTP is valid and not expired
    3. Returns a success response if valid
    
    For security reasons, it returns a generic error response
    if the OTP is invalid or expired.
    """
    permission_classes = [AllowAny]
    authentication_classes = []
    
    def post(self, request, tenant_slug=None, *args, **kwargs):
        """
        Verify the OTP sent to the tenant admin's email.
        
        Request body:
        - email: string (required) - The email of the tenant admin
        - otp: string (required) - The OTP code that was verified
        
        Returns:
        - 200 OK: OTP verified successfully
        - 400 Bad Request: If email or OTP is not provided, or OTP is invalid
        """
        # Log the request
        logger.debug(f"OTP verification request for tenant: {tenant_slug}")
        
        # Validate input
        email = request.data.get('email')
        otp = request.data.get('otp')
        
        if not email or not otp:
            return Response(
                {"detail": "Email and OTP are required."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Store original schema to switch back later
        original_schema = connection.schema_name
        logger.debug(f"Original schema: {original_schema}")
        
        try:
            # Find the tenant
            try:
                tenant = Tenant.objects.get(url_suffix=tenant_slug)
                logger.debug(f"Found tenant: {tenant.schema_name}")
            except Tenant.DoesNotExist:
                logger.debug(f"Tenant not found: {tenant_slug}")
                return Response(
                    {"detail": "Invalid or expired OTP."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Switch to tenant schema
            connection.set_tenant(tenant)
            logger.debug(f"Switched to schema: {connection.schema_name}")
            
            # Check if user exists and is a tenant admin
            try:
                user = User.objects.get(email__iexact=email)
                logger.debug(f"Found user: {user.id} - {user.email}")
                
                # Check if user is a tenant admin
                try:
                    profile = UserProfile.objects.get(user=user)
                    if not profile.is_tenant_admin:
                        logger.debug(f"User {user.email} is not a tenant admin")
                        # Switch back to original schema
                        connection.set_schema_to_public()
                        return Response(
                            {"detail": "Invalid or expired OTP."},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                except UserProfile.DoesNotExist:
                    logger.debug(f"User profile not found for user: {user.email}")
                    # Switch back to original schema
                    connection.set_schema_to_public()
                    return Response(
                        {"detail": "Invalid or expired OTP."},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # User exists and is a tenant admin, proceed with OTP verification
                
                # Switch to public schema for OTP operations
                connection.set_schema_to_public()
                logger.debug(f"Switched to public schema for OTP operations")
                
                # Find the most recent OTP record for this user
                try:
                    otp_record = OTP.objects.filter(
                        user=user, 
                        otp_code=otp
                    ).order_by('-created_at').first()
                    
                    if not otp_record:
                        logger.debug(f"OTP not found for user: {user.email}")
                        return Response(
                            {"detail": "Invalid or expired OTP."},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                    
                    # Check if OTP has expired
                    if timezone.now() > otp_record.expires_at:
                        logger.debug(f"OTP expired for user: {user.email}")
                        # Delete the expired OTP
                        otp_record.delete()
                        return Response(
                            {"detail": "Invalid or expired OTP."},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                    
                    logger.debug(f"OTP verified successfully for user: {user.email}")
                    
                    # Delete the used OTP for security
                    otp_record.delete()
                    
                    # Return success response
                    return Response(
                        {
                            "message": "OTP verified successfully.",
                            "email": email,
                            "user_id": user.id
                        },
                        status=status.HTTP_200_OK
                    )
                except Exception as e:
                    logger.error(f"Error in OTP verification: {str(e)}")
                    # Ensure we switch back to the original schema
                    connection.set_schema_to_public()
                    # Return a generic error message
                    return Response(
                        {"detail": "An error occurred while processing your request."},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )
                
            except User.DoesNotExist:
                logger.debug(f"User not found with email: {email}")
                # Switch back to original schema
                connection.set_schema_to_public()
                return Response(
                    {"detail": "Invalid or expired OTP."},
                    status=status.HTTP_400_BAD_REQUEST
                )
                
        except Exception as e:
            logger.error(f"Error in OTP verification: {str(e)}")
            # Ensure we switch back to the original schema
            connection.set_schema_to_public()
            # Return a generic error message
            return Response(
                {"detail": "An error occurred while processing your request."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        finally:
            # Make sure we always switch back to the original schema
            if connection.schema_name != original_schema:
                connection.set_schema_to_public()
                logger.debug("Switched back to public schema")

class TenantAdminRequestPasswordResetView(APIView):
    """
    API endpoint for tenant admins to request a password reset.
    
    This view handles the initial step of the forgot password flow:
    1. Validates the email exists in the tenant's schema
    2. Generates and stores a secure OTP
    3. Sends the OTP to the user's email
    
    For security reasons, it returns a generic success response
    regardless of whether the user exists or not.
    """
    permission_classes = [AllowAny]
    authentication_classes = []
    
    def post(self, request, tenant_slug=None, *args, **kwargs):
        """
        Process a password reset request for a tenant admin.
        
        Request body:
        - email: string (required) - The email of the tenant admin
        
        Returns:
        - 200 OK: Generic success message (regardless of whether user exists)
        - 400 Bad Request: If email is not provided
        """
        # Log the request
        logger.debug(f"Password reset request for tenant: {tenant_slug}")
        
        # Validate input
        email = request.data.get('email')
        if not email:
            return Response(
                {"detail": "Email is required."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Store original schema to switch back later
        original_schema = connection.schema_name
        logger.debug(f"Original schema: {original_schema}")
        
        try:
            # Find the tenant
            try:
                tenant = Tenant.objects.get(url_suffix=tenant_slug)
                logger.debug(f"Found tenant: {tenant.schema_name}")
            except Tenant.DoesNotExist:
                logger.debug(f"Tenant not found: {tenant_slug}")
                # Return generic success response for security
                return Response(
                    {"detail": "If an account exists for this email, an OTP has been sent."},
                    status=status.HTTP_200_OK
                )
            
            # Switch to tenant schema
            connection.set_tenant(tenant)
            logger.debug(f"Switched to schema: {connection.schema_name}")
            
            # Check if user exists and is a tenant admin
            try:
                user = User.objects.get(email__iexact=email)
                logger.debug(f"Found user: {user.id} - {user.email}")
                
                # Check if user is a tenant admin
                try:
                    profile = UserProfile.objects.get(user=user)
                    if not profile.is_tenant_admin:
                        logger.debug(f"User {user.email} is not a tenant admin")
                        # Switch back to original schema
                        connection.set_schema_to_public()
                        # Return generic success response for security
                        return Response(
                            {"detail": "If an account exists for this email, an OTP has been sent."},
                            status=status.HTTP_200_OK
                        )
                except UserProfile.DoesNotExist:
                    logger.debug(f"User profile not found for user: {user.email}")
                    # Switch back to original schema
                    connection.set_schema_to_public()
                    # Return generic success response for security
                    return Response(
                        {"detail": "If an account exists for this email, an OTP has been sent."},
                        status=status.HTTP_200_OK
                    )
                
                # User exists and is a tenant admin, proceed with OTP generation
                
                # Generate a secure 6-digit OTP
                otp_code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
                logger.debug(f"Generated OTP: {otp_code}")
                
                # Switch to public schema for OTP operations
                connection.set_schema_to_public()
                logger.debug(f"Switched to public schema for OTP operations")
                
                # Delete any existing OTPs for this user
                OTP.objects.filter(user=user).delete()
                
                # Create new OTP record with 10-minute expiry
                expires_at = timezone.now() + timezone.timedelta(minutes=10)
                otp_record = OTP.objects.create(
                    user=user,
                    otp_code=otp_code,
                    expires_at=expires_at
                )
                logger.debug(f"Created OTP record: {otp_record.id}, expires at: {expires_at}")
                
                # Send email with OTP using ZeptoMail
                subject = f"Password Reset OTP for {tenant.name} Tenant Admin"
                html_content = f"""
                <html>
                <body>
                    <h2>Password Reset Request</h2>
                    <p>Hello,</p>
                    <p>You have requested to reset your password for your tenant admin account at <strong>{tenant.name}</strong>.</p>
                    <p>Your One-Time Password (OTP) is: <strong>{otp_code}</strong></p>
                    <p>This OTP will expire in 10 minutes.</p>
                    <p>If you did not request this password reset, please ignore this email.</p>
                    <p>Regards,<br>The {tenant.name} Team</p>
                </body>
                </html>
                """
                
                text_content = f"""
                Password Reset Request
                
                Hello,
                
                You have requested to reset your password for your tenant admin account at {tenant.name}.
                
                Your One-Time Password (OTP) is: {otp_code}
                
                This OTP will expire in 10 minutes.
                
                If you did not request this password reset, please ignore this email.
                
                Regards,
                The {tenant.name} Team
                """
                
                # Use ZeptoMail client to send the email
                zeptomail_client = ZeptoMailClient()
                email_result = zeptomail_client.send_email(
                    to_email=email,
                    subject=subject,
                    html_content=html_content,
                    text_content=text_content
                )
                
                if email_result.get('status') == 'success':
                    logger.debug(f"Password reset email sent to: {email} via ZeptoMail")
                else:
                    logger.error(f"Failed to send password reset email via ZeptoMail: {email_result.get('message')}")
                    # Fallback to Django's send_mail if ZeptoMail fails
                    try:
                        from django.core.mail import send_mail
                        
                        send_mail(
                            subject,
                            text_content,
                            settings.DEFAULT_FROM_EMAIL,
                            [email],
                            fail_silently=False,
                            html_message=html_content
                        )
                        logger.debug(f"Password reset email sent to: {email} via Django's send_mail (fallback)")
                    except Exception as e:
                        logger.error(f"Failed to send password reset email via Django's send_mail: {str(e)}")
                        # Don't reveal the error to the client, but log it for debugging
                        print(f"Email sending error: {str(e)}")
                        # If in DEBUG mode, print the OTP to the console for testing
                        if settings.DEBUG:
                            print(f"DEBUG MODE: OTP for {email}: {otp_code}")
                
                # Return generic success response
                return Response(
                    {"detail": "If an account exists for this email, an OTP has been sent."},
                    status=status.HTTP_200_OK
                )
                
            except User.DoesNotExist:
                logger.debug(f"User not found with email: {email}")
                # Switch back to original schema
                connection.set_schema_to_public()
                # Return generic success response for security
                return Response(
                    {"detail": "If an account exists for this email, an OTP has been sent."},
                    status=status.HTTP_200_OK
                )
                
        except Exception as e:
            logger.error(f"Error in password reset request: {str(e)}")
            # Ensure we switch back to the original schema
            connection.set_schema_to_public()
            # Return a generic error message
            return Response(
                {"detail": "An error occurred while processing your request."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        finally:
            # Make sure we always switch back to the original schema
            if connection.schema_name != original_schema:
                connection.set_schema_to_public()
                logger.debug("Switched back to public schema")

class TenantAdminResetPasswordView(APIView):
    """
    API endpoint for tenant admins to reset their password after OTP verification.
    
    This view handles the final step of the forgot password flow:
    1. Re-validates the email and OTP for security
    2. Sets the new password for the tenant admin
    3. Deletes the OTP to prevent reuse
    """
    permission_classes = [AllowAny]
    authentication_classes = []
    
    def post(self, request, tenant_slug=None, *args, **kwargs):
        """
        Reset the password for a tenant admin after OTP verification.
        
        Request body:
        - email: string (required) - The email of the tenant admin
        - otp: string (required) - The OTP code that was verified
        - new_password: string (required) - The new password to set
        
        Returns:
        - 200 OK: Password reset successfully
        - 400 Bad Request: If inputs are invalid or OTP verification fails
        """
        # Log the request
        logger.debug(f"Password reset request for tenant: {tenant_slug}")
        
        # Validate input
        email = request.data.get('email')
        otp = request.data.get('otp')
        new_password = request.data.get('new_password')
        
        if not email:
            return Response(
                {"detail": "Email is required."},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        if not otp:
            return Response(
                {"detail": "OTP is required."},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        if not new_password:
            return Response(
                {"detail": "New password is required."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validate password strength
        if len(new_password) < 8:
            return Response(
                {"detail": "Password must be at least 8 characters long."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Store original schema to switch back later
        original_schema = connection.schema_name
        logger.debug(f"Original schema: {original_schema}")
        
        try:
            # Find the tenant
            try:
                tenant = Tenant.objects.get(url_suffix=tenant_slug)
                logger.debug(f"Found tenant: {tenant.schema_name}")
            except Tenant.DoesNotExist:
                logger.debug(f"Tenant not found: {tenant_slug}")
                return Response(
                    {"detail": "Invalid request. Please try again."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Switch to tenant schema
            connection.set_tenant(tenant)
            logger.debug(f"Switched to schema: {connection.schema_name}")
            
            # Check if user exists and is a tenant admin
            try:
                user = User.objects.get(email__iexact=email)
                logger.debug(f"Found user: {user.id} - {user.email}")
                
                # Check if user is a tenant admin
                try:
                    profile = UserProfile.objects.get(user=user)
                    if not profile.is_tenant_admin:
                        logger.debug(f"User {user.email} is not a tenant admin")
                        # Switch back to original schema
                        connection.set_schema_to_public()
                        return Response(
                            {"detail": "Invalid request. Please try again."},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                except UserProfile.DoesNotExist:
                    logger.debug(f"User profile not found for user: {user.email}")
                    # Switch back to original schema
                    connection.set_schema_to_public()
                    return Response(
                        {"detail": "Invalid request. Please try again."},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # User exists and is a tenant admin, proceed with OTP re-verification
                
                # Switch to public schema for OTP operations
                connection.set_schema_to_public()
                logger.debug(f"Switched to public schema for OTP operations")
                
                # Find the most recent OTP record for this user
                try:
                    otp_record = OTP.objects.filter(
                        user=user, 
                        otp_code=otp
                    ).order_by('-created_at').first()
                    
                    if not otp_record:
                        logger.debug(f"OTP not found for user: {user.email}")
                        return Response(
                            {"detail": "Invalid request. Please try again."},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                    
                    # Check if OTP has expired
                    if timezone.now() > otp_record.expires_at:
                        logger.debug(f"OTP expired for user: {user.email}")
                        # Delete the expired OTP
                        otp_record.delete()
                        return Response(
                            {"detail": "OTP has expired. Please request a new password reset."},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                    
                    logger.debug(f"OTP re-verified successfully for user: {user.email}")
                    
                    # Delete the used OTP immediately to prevent reuse
                    otp_record.delete()
                    logger.debug(f"Deleted OTP for security")
                    
                    # Set the new password
                    user.set_password(new_password)
                    user.save()
                    logger.debug(f"Password updated successfully for user: {user.email}")
                    
                    # Return success response
                    return Response(
                        {"message": "Password reset successfully."},
                        status=status.HTTP_200_OK
                    )
                    
                except Exception as e:
                    logger.error(f"Error verifying OTP: {str(e)}")
                    return Response(
                        {"detail": "Invalid request. Please try again."},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
            except User.DoesNotExist:
                logger.debug(f"User not found with email: {email}")
                # Switch back to original schema
                connection.set_schema_to_public()
                return Response(
                    {"detail": "Invalid request. Please try again."},
                    status=status.HTTP_400_BAD_REQUEST
                )
                
        except Exception as e:
            logger.error(f"Error in password reset: {str(e)}")
            # Ensure we switch back to the original schema
            connection.set_schema_to_public()
            # Return a generic error message
            return Response(
                {"detail": "An error occurred while processing your request."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        finally:
            # Make sure we always switch back to the original schema
            if connection.schema_name != original_schema:
                connection.set_schema_to_public()
                logger.debug("Switched back to public schema")

class RoleViewSet(ModelViewSet):
    """
    ViewSet for managing roles.
    
    Tenant admins (users with is_staff=True and is_tenant_admin=True in their profile)
    are granted full access to all role management features regardless of specific
    role-based permissions.
    """
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    permission_classes = [IsTenantAdmin]
    
    def get_queryset(self):
        """
        Override to filter roles for the current tenant.
        """
        import logging
        logger = logging.getLogger(__name__)
        
        logger.info(f"RoleViewSet.get_queryset called by {self.request.user} on {self.request.path}")
        
        # Check if we're in a tenant context
        if hasattr(self.request, 'tenant') and self.request.tenant:
            logger.info(f"In tenant context: {self.request.tenant.schema_name}")
            return Role.objects.all()
        else:
            logger.warning(f"No tenant context found, returning empty queryset")
            return Role.objects.none()
    
    def get_permissions(self):
        """
        Override to use different permissions for different actions.
        
        Tenant admins (users with is_staff=True and is_tenant_admin=True in their profile)
        are granted full access to all role management features regardless of specific
        role-based permissions.
        """
        # For the debug_roles action, allow access without authentication
        if self.action == 'debug_roles':
            return []
            
        # Use the IsTenantAdmin permission class for all actions
        # This ensures that any user who is a tenant admin has full access
        return [IsTenantAdmin()]
    
    @action(detail=False, methods=['get'])
    def tenant_admin_roles(self, request):
        """
        Special endpoint for tenant admins to access roles without requiring specific permissions.
        """
        import logging
        logger = logging.getLogger(__name__)
        
        logger.info(f"tenant_admin_roles action called by {request.user}")
        
        # Check if the user is a tenant admin
        from ecomm_tenant.ecomm_tenant_admins.models import UserProfile
        try:
            if hasattr(request.user, 'is_staff') and request.user.is_staff and UserProfile.objects.filter(user=request.user, is_tenant_admin=True).exists():
                # User is a tenant admin, return all roles
                roles = self.get_queryset()
                serializer = self.get_serializer(roles, many=True)
                return Response(serializer.data)
            else:
                logger.warning(f"User {request.user} is not a tenant admin")
                return Response({"detail": "Only tenant administrators are authorized to perform this action."}, status=status.HTTP_403_FORBIDDEN)
        except Exception as e:
            logger.error(f"Error in tenant_admin_roles: {str(e)}", exc_info=True)
            return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
    @action(detail=False, methods=['get'], url_path='debug-roles')
    def debug_roles(self, request, tenant_slug=None):
        """
        Debug endpoint to view roles without authentication (for development only).
        """
        import logging
        logger = logging.getLogger(__name__)
        
        logger.info(f"debug_roles action called on {request.path} for tenant {tenant_slug}")
        
        # Check if we're in a tenant context
        if hasattr(request, 'tenant') and request.tenant:
            logger.info(f"In tenant context: {request.tenant.schema_name}")
            roles = Role.objects.all()
            logger.info(f"Found {roles.count()} roles")
            serializer = self.get_serializer(roles, many=True)
            return Response(serializer.data)
        else:
            logger.warning(f"No tenant context found")
            return Response({"detail": "No tenant context found"}, status=status.HTTP_400_BAD_REQUEST)

class PermissionViewSet(ModelViewSet):
    """
    ViewSet for managing permissions.
    """
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer
    permission_classes = [IsTenantAdmin]
    http_method_names = ['get', 'head', 'options']  # Read-only

    def get_permissions(self):
        """
        Override to use different permissions for different actions.
        
        Tenant admins (users with is_staff=True and is_tenant_admin=True in their profile)
        are granted full access to all permission management features regardless of specific
        role-based permissions.
        """
        # Use the IsTenantAdmin permission class for all actions
        # This ensures that any user who is a tenant admin has full access
        return [IsTenantAdmin()]

class UserRoleViewSet(ModelViewSet):
    """
    ViewSet for managing user roles.
    """
    queryset = UserRole.objects.all()
    serializer_class = UserRoleSerializer
    permission_classes = [HasTenantPermission('assign_roles')]
    
    def get_permissions(self):
        """
        Override to use different permissions for different actions.
        
        Tenant admins (users with is_staff=True and is_tenant_admin=True in their profile)
        are granted full access to all user role management features regardless of specific
        role-based permissions.
        """
        # Check if the user is a tenant admin first
        if hasattr(self.request, 'user') and self.request.user.is_authenticated:
            try:
                from ecomm_tenant.ecomm_tenant_admins.models import UserProfile
                if (hasattr(self.request.user, 'is_staff') and self.request.user.is_staff and 
                    UserProfile.objects.filter(user=self.request.user, is_tenant_admin=True).exists()):
                    # User is a tenant admin, grant full access
                    return [IsTenantAdmin()]
            except Exception as e:
                # Log the error but continue with normal permission checks
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"Error checking tenant admin status: {str(e)}")
        
        # Fall back to the default permission for non-tenant admins
        return [HasTenantPermission('assign_roles')]
    
    def get_queryset(self):
        """
        Filter queryset to only show roles for the specified user.
        """
        queryset = UserRole.objects.all()
        user_id = self.request.query_params.get('user_id', None)
        
        if user_id is not None:
            queryset = queryset.filter(user_id=user_id)
            
        return queryset
    
    def create(self, request, *args, **kwargs):
        """
        Assign a role to a user.
        """
        user_id = request.data.get('user_id')
        role_id = request.data.get('role_id')
        
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )
            
        try:
            role = Role.objects.get(id=role_id)
        except Role.DoesNotExist:
            return Response(
                {'error': 'Role not found'},
                status=status.HTTP_404_NOT_FOUND
            )
            
        # Check if the user already has this role
        existing_user_role = UserRole.objects.filter(user=user, role=role).first()
        if existing_user_role:
            logger.info(f"UserRole already exists with ID: {existing_user_role.id}")
            user_role = existing_user_role
        else:
            # Create new UserRole with auto-generated ID
            user_role = UserRole.objects.create(
                user=user,
                role=role
            )
            logger.info(f"Created UserRole with ID: {user_role.id}")
        
        serializer = self.get_serializer(user_role)
        return Response(
            serializer.data,
            status=status.HTTP_201_CREATED
        )

class TenantViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows platform admins to manage tenants.
    
    Provides CRUD operations for Tenant objects with appropriate permissions
    and validation for tenant management.
    """
    queryset = Tenant.objects.all().order_by('-created_at')
    serializer_class = TenantSerializer
    
    def get_permissions(self):
        """
        Ensure only staff users can access this viewset.
        """
        return [permissions.IsAuthenticated(), permissions.IsAdminUser()]
    
    def create(self, request, *args, **kwargs):
        """
        Create a new tenant with auto-generated schema_name and initial admin user.
        
        The request should include:
        - Tenant details (name, url_suffix, etc.)
        - Initial admin user details (email, first_name, last_name, password)
        """
        # Get the serializer and validate data
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Extract admin user data from validated serializer data
        admin_email = serializer.validated_data.pop('admin_email', None)
        admin_first_name = serializer.validated_data.pop('admin_first_name', None)
        admin_last_name = serializer.validated_data.pop('admin_last_name', None)
        admin_password = serializer.validated_data.pop('admin_password', None)
        
        # Validate required admin fields
        errors = {}
        if not admin_email:
            errors['admin_email'] = ['This field is required.']
        elif not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', admin_email):
            errors['admin_email'] = ['Enter a valid email address.']
            
        if not admin_first_name:
            errors['admin_first_name'] = ['This field is required.']
        if not admin_last_name:
            errors['admin_last_name'] = ['This field is required.']
            
        # If there are validation errors, return them
        if errors:
            return Response(
                {
                    'status': 'error',
                    'message': 'Invalid admin user data',
                    'errors': errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )
            
        # Generate a random password if not provided
        if not admin_password:
            admin_password = ''.join(random.choices(
                string.ascii_uppercase + string.ascii_lowercase + string.digits, 
                k=12
            ))
        
        # Create the tenant first (no transaction)
        tenant = serializer.save()
        
        try:
            # Import necessary models and functions
            from django.db import connection
            import psycopg2
            from django.conf import settings
            
            # Get database connection info from settings
            db_settings = settings.DATABASES['default']
            
            # Create a direct connection to PostgreSQL to create the schema and tables
            conn = psycopg2.connect(
                dbname=db_settings['NAME'],
                user=db_settings['USER'],
                password=db_settings['PASSWORD'],
                host=db_settings['HOST'],
                port=db_settings['PORT']
            )
            conn.autocommit = True  # Important for schema creation
            
            try:
                with conn.cursor() as cursor:
                    # Create the schema if it doesn't exist
                    cursor.execute(f"CREATE SCHEMA IF NOT EXISTS {tenant.schema_name}")
                    
                    # Create auth_user table in the tenant schema if it doesn't exist
                    cursor.execute(f"""
                        CREATE TABLE IF NOT EXISTS {tenant.schema_name}.auth_user (
                            id SERIAL PRIMARY KEY,
                            password VARCHAR(128) NOT NULL,
                            last_login TIMESTAMP WITH TIME ZONE NULL,
                            is_superuser BOOLEAN NOT NULL,
                            username VARCHAR(150) NOT NULL UNIQUE,
                            first_name VARCHAR(150) NOT NULL,
                            last_name VARCHAR(150) NOT NULL,
                            email VARCHAR(254) NOT NULL,
                            is_staff BOOLEAN NOT NULL,
                            is_active BOOLEAN NOT NULL,
                            date_joined TIMESTAMP WITH TIME ZONE NOT NULL
                        )
                    """)
                    
                    # Insert the admin user into the auth_user table
                    cursor.execute(f"""
                        INSERT INTO {tenant.schema_name}.auth_user 
                        (password, last_login, is_superuser, username, first_name, last_name, email, is_staff, is_active, date_joined)
                        VALUES (%s, NULL, FALSE, %s, %s, %s, %s, TRUE, TRUE, NOW())
                        RETURNING id
                    """, [
                        make_password(admin_password),
                        admin_email,
                        admin_first_name,
                        admin_last_name,
                        admin_email
                    ])
                    
                    # Get the user ID
                    user_id = cursor.fetchone()[0]
                    
                    # Create the company table if it doesn't exist
                    cursor.execute(f"""
                        CREATE TABLE IF NOT EXISTS {tenant.schema_name}.authentication_company (
                            id SERIAL PRIMARY KEY,
                            name VARCHAR(255) NOT NULL,
                            tenant_id INTEGER NOT NULL,
                            created_at TIMESTAMP WITH TIME ZONE NOT NULL,
                            updated_at TIMESTAMP WITH TIME ZONE NOT NULL
                        )
                    """)
                    
                    # Insert the company
                    cursor.execute(f"""
                        INSERT INTO {tenant.schema_name}.authentication_company
                        (name, tenant_id, created_at, updated_at)
                        VALUES (%s, %s, NOW(), NOW())
                        RETURNING id
                    """, [
                        tenant.name,
                        tenant.id
                    ])
                    
                    # Get the company ID
                    company_id = cursor.fetchone()[0]
                    
                    # Create the userprofile table if it doesn't exist
                    cursor.execute(f"""
                        CREATE TABLE IF NOT EXISTS {tenant.schema_name}.authentication_userprofile (
                            id SERIAL PRIMARY KEY,
                            user_id INTEGER NOT NULL UNIQUE,
                            company_id INTEGER NULL,
                            nationality VARCHAR(100) NULL,
                            is_company_admin BOOLEAN NOT NULL,
                            is_tenant_admin BOOLEAN NOT NULL,
                            is_email_verified BOOLEAN NOT NULL,
                            otp VARCHAR(6) NULL,
                            totp_secret VARCHAR(255) NULL,
                            is_2fa_enabled BOOLEAN NOT NULL,
                            needs_2fa_setup BOOLEAN NOT NULL,
                            recovery_codes JSONB NULL,
                            created_at TIMESTAMP WITH TIME ZONE NOT NULL,
                            updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
                            FOREIGN KEY (user_id) REFERENCES {tenant.schema_name}.auth_user(id),
                            FOREIGN KEY (company_id) REFERENCES {tenant.schema_name}.authentication_company(id)
                        )
                    """)
                    
                    # Insert the user profile
                    cursor.execute(f"""
                        INSERT INTO {tenant.schema_name}.authentication_userprofile
                        (user_id, company_id, nationality, is_company_admin, is_tenant_admin, is_email_verified,
                         otp, totp_secret, is_2fa_enabled, needs_2fa_setup, recovery_codes, created_at, updated_at)
                        VALUES (%s, %s, NULL, TRUE, TRUE, TRUE, NULL, NULL, FALSE, FALSE, NULL, NOW(), NOW())
                    """, [
                        user_id,
                        company_id
                    ])
                    
                    # Create the role table if it doesn't exist
                    cursor.execute(f"""
                        CREATE TABLE IF NOT EXISTS {tenant.schema_name}.ecomm_tenant_admins_role (
                            id SERIAL PRIMARY KEY,
                            name VARCHAR(100) NOT NULL UNIQUE,
                            description TEXT NOT NULL,
                            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
                        )
                    """)
                    
                    # Insert the tenant_admin role
                    cursor.execute(f"""
                        INSERT INTO {tenant.schema_name}.ecomm_tenant_admins_role
                        (name, description, created_at, updated_at)
                        VALUES ('tenant_admin', 'Tenant administrator with full access to tenant resources', NOW(), NOW())
                        RETURNING id
                    """)
                    
                    # Get the role ID
                    role_id = cursor.fetchone()[0]
                    
                    # Create the permission table if it doesn't exist
                    cursor.execute(f"""
                        CREATE TABLE IF NOT EXISTS {tenant.schema_name}.ecomm_tenant_admins_permission (
                            id SERIAL PRIMARY KEY,
                            name VARCHAR(100) NOT NULL UNIQUE,
                            description TEXT NOT NULL,
                            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
                        )
                    """)
                    
                    # Create the role_permission table if it doesn't exist
                    cursor.execute(f"""
                        CREATE TABLE IF NOT EXISTS {tenant.schema_name}.ecomm_tenant_admins_rolepermission (
                            id SERIAL PRIMARY KEY,
                            role_id INTEGER NOT NULL,
                            permission_id INTEGER NOT NULL,
                            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                            FOREIGN KEY (role_id) REFERENCES {tenant.schema_name}.ecomm_tenant_admins_role(id),
                            FOREIGN KEY (permission_id) REFERENCES {tenant.schema_name}.ecomm_tenant_admins_permission(id),
                            UNIQUE (role_id, permission_id)
                        )
                    """)
                    
                    # Create the userrole table if it doesn't exist
                    cursor.execute(f"""
                        CREATE TABLE IF NOT EXISTS {tenant.schema_name}.ecomm_tenant_admins_userrole (
                            id SERIAL PRIMARY KEY,
                            user_id INTEGER NOT NULL,
                            role_id INTEGER NOT NULL,
                            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                            updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                            FOREIGN KEY (user_id) REFERENCES {tenant.schema_name}.auth_user(id),
                            FOREIGN KEY (role_id) REFERENCES {tenant.schema_name}.ecomm_tenant_admins_role(id),
                            UNIQUE (user_id, role_id)
                        )
                    """)
                    
                    # Insert the user role
                    cursor.execute(f"""
                        INSERT INTO {tenant.schema_name}.ecomm_tenant_admins_userrole
                        (user_id, role_id, created_at, updated_at)
                        VALUES (%s, %s, NOW(), NOW())
                    """, [
                        user_id,
                        role_id
                    ])
                
                # Send welcome email directly using ZeptoMail API
                try:
                    from .utils import send_tenant_admin_welcome_email_direct
                    
                    # Construct the tenant URL
                    if tenant.custom_domain:
                        tenant_url = f"https://{tenant.custom_domain}"
                    else:
                        # Use the base URL with the tenant's URL suffix
                        # In development, this would be localhost:3000/{url_suffix}
                        # In production, it would be the actual domain
                        base_url = "http://localhost:3000"  # Development default
                        if hasattr(settings, 'FRONTEND_BASE_URL') and settings.FRONTEND_BASE_URL:
                            base_url = settings.FRONTEND_BASE_URL
                        
                        tenant_url = f"{base_url}/{tenant.url_suffix}"
                    
                    # Send the welcome email
                    send_tenant_admin_welcome_email_direct(
                        email=admin_email,
                        first_name=admin_first_name,
                        password=admin_password,
                        tenant_name=tenant.name,
                        tenant_url=tenant_url
                    )
                    logger.info(f"Welcome email sent to tenant admin {admin_email} for tenant {tenant.name}")
                except Exception as email_error:
                    # Log the error but don't fail the tenant creation
                    logger.error(f"Failed to send welcome email: {str(email_error)}")
                    logger.warning("Tenant creation will proceed despite email sending failure")
            finally:
                # Close the connection
                conn.close()
            
            # Return success response with tenant and admin details
            headers = self.get_success_headers(serializer.data)
            return Response(
                {
                    'status': 'success',
                    'message': 'Tenant created successfully with admin user',
                    'data': {
                        'tenant': serializer.data,
                        'admin_user': {
                            'email': admin_email,
                            'first_name': admin_first_name,
                            'last_name': admin_last_name,
                            'password': admin_password if settings.DEBUG else None
                        }
                    }
                },
                status=status.HTTP_201_CREATED, 
                headers=headers
            )
            
        except Exception as e:
            # If there's an error creating the admin user, delete the tenant
            tenant.delete()
            
            # Log the error and return an error response
            logger.error(f"Error creating tenant admin: {str(e)}")
            return Response(
                {
                    'status': 'error',
                    'message': 'Failed to create tenant admin user',
                    'errors': {'admin_user': [str(e)]}
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def update(self, request, *args, **kwargs):
        """
        Update a tenant while preventing schema_name changes.
        """
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        
        # Prevent changing schema_name
        if 'schema_name' in request.data and request.data['schema_name'] != instance.schema_name:
            return Response(
                {
                    'status': 'error',
                    'message': 'Changing schema_name is not allowed',
                    'errors': {'schema_name': ['This field cannot be modified.']}
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        
        if getattr(instance, '_prefetched_objects_cache', None):
            # If 'prefetch_related' has been applied to a queryset, we need to
            # forcibly invalidate the prefetch cache on the instance.
            instance._prefetched_objects_cache = {}
        
        return Response(
            {
                'status': 'success',
                'message': 'Tenant updated successfully',
                'data': serializer.data
            }
        )
    
    def destroy(self, request, *args, **kwargs):
        """
        Delete a tenant with confirmation response.
        """
        instance = self.get_object()
        tenant_name = instance.name
        
        self.perform_destroy(instance)
        
        return Response(
            {
                'status': 'success',
                'message': f'Tenant "{tenant_name}" deleted successfully'
            },
            status=status.HTTP_200_OK
        )
    
    def list(self, request, *args, **kwargs):
        """
        List all tenants with pagination.
        """
        queryset = self.filter_queryset(self.get_queryset())
        
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = self.get_serializer(queryset, many=True)
        return Response(
            {
                'status': 'success',
                'count': queryset.count(),
                'data': serializer.data
            }
        )
    
    def retrieve(self, request, *args, **kwargs):
        """
        Retrieve a specific tenant.
        """
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        
        return Response(
            {
                'status': 'success',
                'data': serializer.data
            }
        )

class TenantUserViewSet(ModelViewSet):
    """
    ViewSet for managing tenant users.
    
    This viewset provides CRUD operations for TenantUser objects with appropriate
    permissions and validation. Only tenant admins can manage tenant users.
    
    The TenantRoutingMiddleware ensures that this viewset only operates on
    users within the current tenant's schema.
    """
    model = TenantUser
    permission_classes = [IsAuthenticated, IsCurrentTenantAdmin]
    
    def get_serializer_class(self):
        """
        Return different serializers based on the action.
        """
        if self.action == 'create':
            return TenantUserCreateSerializer
        return TenantUserDisplaySerializer
    
    def get_queryset(self):
        """
        Return all tenant users in the current tenant schema.
        
        The TenantRoutingMiddleware ensures this only queries the current tenant's schema.
        """
        queryset = TenantUser.objects.all()
        
        # Add filtering options
        email = self.request.query_params.get('email', None)
        if email:
            queryset = queryset.filter(email__icontains=email)
        
        # Add ordering options
        ordering = self.request.query_params.get('ordering', 'email')
        if ordering not in ['email', 'first_name', 'last_name', 'date_joined', '-email', '-first_name', '-last_name', '-date_joined']:
            ordering = 'email'
        
        return queryset.order_by(ordering)
    
    @transaction.atomic
    def perform_create(self, serializer):
        """
        Create a new tenant user with the validated data.
        
        This method:
        1. Extracts role_id and user_type from validated_data
        2. Generates a password if not provided
        3. Creates the TenantUser using create_user()
        4. Creates the associated UserProfile
        5. Creates a UserRole linking the user and role if role is provided
        6. Sends a welcome email with the credentials
        """
        try:
            # Extract validated data
            validated_data = serializer.validated_data
            
            # Log the validated data for debugging (excluding password)
            debug_data = {k: v for k, v in validated_data.items() if k != 'password'}
            logger.info(f"Creating tenant user with data: {debug_data}")
            
            # Get role object (now required)
            role = validated_data.pop('role_id', None)
            if not role:
                logger.error("Role is required but not provided")
                raise serializers.ValidationError({"role_id": "Role assignment is required."})
            logger.info(f"Role: {role}")
            
            # Get user type (internal or external)
            user_type = validated_data.pop('user_type', 'external')
            logger.info(f"User type: {user_type}")
            
            # Check if we should generate a password or use the provided one
            generate_password = validated_data.pop('generate_password', True)
            logger.info(f"Generate password: {generate_password}")
            
            # Generate password if needed
            generated_password = None
            if generate_password:
                # Generate a secure random password
                generated_password = TenantUser.objects.make_random_password()
                validated_data['password'] = generated_password
                logger.info("Generated password for new user")
            else:
                # Use the provided password
                if not validated_data.get('password'):
                    logger.error("Password is required when auto-generation is disabled")
                    raise serializers.ValidationError({"password": "Password is required when automatic generation is disabled."})
                logger.info("Using provided password for new user")
            
            # Create the user
            logger.info(f"Creating TenantUser with email: {validated_data['email']}")
            user = TenantUser.objects.create_user(
                email=validated_data['email'],
                password=validated_data['password'],
                first_name=validated_data.get('first_name', ''),
                last_name=validated_data.get('last_name', ''),
                username=validated_data['email'],  # Use email as username
                is_staff=user_type == 'internal'  # Set is_staff based on user_type
            )
            logger.info(f"Created TenantUser with ID: {user.id}")
            
            # Get the tenant's company
            company = None
            if hasattr(self.request, 'tenant') and hasattr(self.request.tenant, 'companies'):
                # Try to get the first company associated with this tenant
                company = self.request.tenant.companies.first()
                if company:
                    logger.info(f"Found company: {company.id}")
                else:
                    logger.warning("No company found for this tenant")
            else:
                logger.warning("Request has no tenant or tenant has no companies attribute")
            
            # Create user profile with safe defaults for any missing fields
            logger.info(f"Creating UserProfile for user: {user.id}")
            profile = UserProfile.objects.create(
                user=user,
                company_id=company,  # Associate with the company
                nationality=validated_data.get('nationality', ''),
                is_company_admin=False,
                is_tenant_admin=False,
                is_email_verified=True,  # Auto-verify since admin is creating
                needs_2fa_setup=True,
                recovery_codes=None,
                created_at=timezone.now(),
                updated_at=timezone.now()
            )
            logger.info(f"Created UserProfile with ID: {profile.id}")
            
            # Assign role to user if provided
            logger.info(f"Assigning role {role.id} to user {user.id}")
            
            # Check if a UserRole already exists for this user and role
            existing_user_role = UserRole.objects.filter(user=user, role=role).first()
            if existing_user_role:
                logger.info(f"UserRole already exists with ID: {existing_user_role.id}")
                user_role = existing_user_role
            else:
                # Create new UserRole with auto-generated ID
                user_role = UserRole.objects.create(
                    user=user,
                    role=role
                )
                logger.info(f"Created UserRole with ID: {user_role.id}")
            
            # Send welcome email with credentials
            try:
                logger.info(f"Sending welcome email to user {user.id}")
                send_new_tenant_user_welcome_email.delay(user.id, generated_password)
                logger.info("Welcome email task queued successfully")
            except Exception as email_error:
                logger.error(f"Error queuing welcome email: {str(email_error)}")
                # Continue execution even if email fails
            
            # Return the user and generated password (if any)
            return {
                'user': user,
                'generated_password': generated_password
            }
        except Exception as e:
            # Log the full error with traceback
            logger.error(f"Error creating tenant user: {str(e)}", exc_info=True)
            # Re-raise the exception to be handled by the DRF exception handler
            raise
    
    def create(self, request, *args, **kwargs):
        """
        Create a new tenant user.
        
        This method overrides the default create method to handle the response
        when a password is auto-generated.
        """
        try:
            logger.info(f"Received request to create tenant user: {request.data}")
            
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            result = self.perform_create(serializer)
            
            # Prepare response data
            user = result['user']
            response_data = {
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'message': 'User created successfully'
            }
            
            # Include generated password in response if one was created
            if result.get('generated_password'):
                response_data['generated_password'] = result['generated_password']
                response_data['message'] += ' with auto-generated password'
            
            logger.info(f"Successfully created tenant user with ID: {user.id}")
            
            headers = self.get_success_headers(serializer.data)
            return Response(response_data, status=status.HTTP_201_CREATED, headers=headers)
        except Exception as e:
            logger.error(f"Error in create method: {str(e)}", exc_info=True)
            # Let DRF handle the exception response
            raise
