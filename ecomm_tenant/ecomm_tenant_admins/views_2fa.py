"""
Views for 2FA functionality.
"""
import base64
import io
import qrcode
import pyotp
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from django.contrib.auth import get_user_model
from .models import UserProfile
from django.contrib.auth import login
from django.utils.decorators import method_decorator
from django.contrib.auth import login

from .authentication import TemporaryTokenAuthentication
from .serializers import (
    TwoFactorSetupSerializer,
    TwoFactorSetupConfirmRequestSerializer,
    TwoFactorSetupConfirmResponseSerializer,
    TwoFactorVerifyRequestSerializer,
    TwoFactorRecoveryVerifyRequestSerializer,
    UserProfileSerializer
)
from .utils import (
    generate_2fa_secret, 
    generate_2fa_uri, 
    verify_2fa_code, 
    generate_recovery_codes, 
    encrypt_secret, 
    decrypt_secret, 
    encrypt_recovery_codes, 
    decrypt_recovery_codes,
    generate_temp_token,
    check_and_fix_recovery_codes,
    check_and_fix_totp_secret
)
from ecomm_tenant.ecomm_tenant_admins.models import UserProfile
from .authentication import TemporaryTokenAuthentication
from django.core.cache import cache
import logging

logger = logging.getLogger(__name__)

User = get_user_model()
class TwoFactorSetupStartView(APIView):
    """
    API endpoint to start the 2FA setup process.
    
    This view generates a new 2FA secret key, creates a QR code for it,
    and stores the encrypted secret in the session for later verification.
    """
    permission_classes = [AllowAny]  # Allow unauthenticated access
    authentication_classes = []  # No authentication required
    serializer_class = TwoFactorSetupSerializer
    
    def post(self, request, *args, **kwargs):
        """
        Start the two-factor authentication setup process.
        
        Returns:
        - 200 OK: {"secret": "...", "qr_code": "..."} if successful
        - 400 Bad Request: {"message": "..."} if request data is invalid
        """
        # Check if user is authenticated or has a temporary token
        user = None
        is_temp_token = False
        
        # Get user from request
        if request.user.is_authenticated:
            user = request.user
        elif 'user_id' in request.data:
            # This is a temporary token flow (forced setup or signup)
            try:
                user_id = request.data.get('user_id')
                user = User.objects.get(id=user_id)
                is_temp_token = True
                
                # Log the temporary token flow
                logger.info(f"Starting 2FA setup with temporary token for user {user_id}")
            except User.DoesNotExist:
                return Response(
                    {"message": "User not found"},
                    status=status.HTTP_404_NOT_FOUND
                )
        
        if not user:
            return Response(
                {"message": "Authentication required"},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        try:
            # Check if user already has 2FA enabled
            profile = UserProfile.objects.get(user=user)
            
            # If this is a forced setup or signup flow, we should allow re-setup
            # even if the user already has 2FA enabled
            if profile.is_2fa_enabled and not is_temp_token:
                return Response(
                    {"message": "Two-factor authentication is already enabled for this account"},
                    status=status.HTTP_400_BAD_REQUEST
                )
        except UserProfile.DoesNotExist:
            # If user profile does not exist, create it
            profile = UserProfile.objects.create(user=user)
        
        # Generate a new secret key
        secret = generate_2fa_secret()
        
        # Generate the provisioning URI for QR code
        uri = generate_2fa_uri(
            secret=secret,
            email=user.email,
            issuer_name="SaaS ERP"
        )
        
        print(f"Generated URI: {uri}")
        print(f"Secret: {secret}")
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert the QR code to base64
        buffer = io.BytesIO()
        img.save(buffer)
        qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
        
        # Store the encrypted secret in the session
        encrypted_secret = encrypt_secret(secret)
        request.session['temp_2fa_secret'] = encrypted_secret
        request.session['temp_2fa_user_id'] = str(user.id)
        
        # Save the session explicitly to ensure it's stored
        request.session.save()
        
        print(f"Stored encrypted secret in session: {encrypted_secret}")
        print(f"Session key: {request.session.session_key}")
        
        # Prepare the response
        response_data = {
            'qr_code': f"data:image/png;base64,{qr_code_base64}",
            'secret': secret,
            'uri': uri
        }
        
        return Response(response_data, status=status.HTTP_200_OK)
        
    def get(self, request, *args, **kwargs):
        """
        Start the 2FA setup process via GET request.
        
        Returns:
        - 200 OK: {"qr_code": "base64_encoded_qr_code", "secret": "plain_text_secret", "uri": "provisioning_uri"} if successful
        - 400 Bad Request: {"error": "Error message"} if there's an error
        """
        return self.post(request, *args, **kwargs)


class TwoFactorSetupConfirmView(APIView):
    """
    API endpoint for confirming two-factor authentication setup.
    """
    permission_classes = [AllowAny]  # Allow unauthenticated access
    authentication_classes = []  # No authentication required
    
    def post(self, request, *args, **kwargs):
        """
        Confirm the two-factor authentication setup.
        
        Returns:
        - 200 OK: {"message": "Two-factor authentication enabled successfully", "recovery_codes": [...]} if successful
        - 400 Bad Request: {"message": "..."} if request data is invalid
        """
        # Get the verification code from the request
        verification_code = request.data.get('verification_code')
        if not verification_code:
            return Response(
                {"message": "Verification code is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get the user ID from the request or session
        user_id = request.data.get('user_id') or request.session.get('temp_2fa_user_id')
        if not user_id:
            return Response(
                {"message": "User ID is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get the encrypted secret from the session
        encrypted_secret = request.session.get('temp_2fa_secret')
        
        # Log for debugging
        print(f"Session key: {request.session.session_key}")
        print(f"User ID from request: {request.data.get('user_id')}")
        print(f"User ID from session: {request.session.get('temp_2fa_user_id')}")
        print(f"Encrypted secret from session: {encrypted_secret}")
        
        if not encrypted_secret:
            # If we can't find the secret in the session, check if this is a signup flow
            is_signup_flow = request.data.get('is_signup_flow')
            
            if is_signup_flow:
                # For signup flow, we need to generate a new secret
                secret = generate_2fa_secret()
                encrypted_secret = encrypt_secret(secret)
                
                # Store the secret in the session
                request.session['temp_2fa_secret'] = encrypted_secret
                request.session['temp_2fa_user_id'] = str(user_id)
                request.session.save()
                
                print(f"Generated new secret for signup flow: {secret}")
                print(f"Encrypted: {encrypted_secret}")
                
                # Verify the code against this new secret
                totp = pyotp.TOTP(secret)
                if not totp.verify(verification_code):
                    return Response(
                        {"message": "Invalid verification code"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            else:
                return Response(
                    {"message": "No 2FA setup in progress. Please start the setup process again."},
                    status=status.HTTP_400_BAD_REQUEST
                )
        else:
            # Decrypt the secret
            try:
                secret = decrypt_secret(encrypted_secret)
                
                # Verify the code
                totp = pyotp.TOTP(secret)
                if not totp.verify(verification_code):
                    return Response(
                        {"message": "Invalid verification code"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            except Exception as e:
                print(f"Error decrypting secret or verifying code: {str(e)}")
                
                # If there's an error, try generating a new secret
                secret = generate_2fa_secret()
                encrypted_secret = encrypt_secret(secret)
                
                # Verify with the new secret
                totp = pyotp.TOTP(secret)
                if not totp.verify(verification_code):
                    return Response(
                        {"message": "Invalid verification code"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
        
        # Get the user
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {"message": "User not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Generate recovery codes
        recovery_codes = generate_recovery_codes()
        encrypted_recovery_codes = encrypt_recovery_codes(recovery_codes)
        
        # Update the user profile
        try:
            profile = UserProfile.objects.get(user=user)
            profile.is_2fa_enabled = True
            profile.totp_secret = encrypted_secret
            profile.recovery_codes = encrypted_recovery_codes
            profile.needs_2fa_setup = False  # Mark that 2FA setup is complete
            profile.save()
        except UserProfile.DoesNotExist:
            # Create a new profile if it doesn't exist
            profile = UserProfile.objects.create(
                user=user,
                is_2fa_enabled=True,
                totp_secret=encrypted_secret,
                recovery_codes=encrypted_recovery_codes,
                needs_2fa_setup=False
            )
        
        # Clear the session data
        if 'temp_2fa_secret' in request.session:
            del request.session['temp_2fa_secret']
        if 'temp_2fa_user_id' in request.session:
            del request.session['temp_2fa_user_id']
        
        # Check if this is a signup or forced setup flow
        is_temp_token = request.data.get('is_temp_token', False)
        
        # Generate a full authentication token if this is a signup or forced setup flow
        token = None
        if is_temp_token:
            # Generate a full authentication token
            from rest_framework_simplejwt.tokens import RefreshToken
            refresh = RefreshToken.for_user(user)
            token = {
                'refresh': str(refresh),
                'access': str(refresh.access_token)
            }
        
        # Prepare the response
        response_data = {
            "message": "Two-factor authentication enabled successfully",
            "recovery_codes": recovery_codes
        }
        
        # Add the token to the response if available
        if token:
            response_data["token"] = token
        
        return Response(response_data, status=status.HTTP_200_OK)


class TwoFactorVerifyIPThrottle(AnonRateThrottle):
    """
    Throttle for 2FA verification by IP address.
    Limits to 5 requests per minute.
    """
    rate = '5/min'
    scope = '2fa_verify_ip'


class TwoFactorVerifyUserThrottle(UserRateThrottle):
    """
    Throttle for 2FA verification by user ID.
    Limits to 10 requests per hour.
    """
    rate = '10/hour'
    scope = '2fa_verify_user'


class TwoFactorVerifyView(APIView):
    """
    API endpoint to verify a 2FA code during login.
    
    This view verifies the TOTP code provided by the user during login,
    and if valid, completes the login process.
    
    Rate limiting is applied to prevent brute-force attacks:
    - 5 attempts per minute per IP address
    - 10 attempts per hour per user ID
    """
    permission_classes = [AllowAny]
    authentication_classes = []  # No authentication required
    throttle_classes = [TwoFactorVerifyIPThrottle, TwoFactorVerifyUserThrottle]
    
    def post(self, request, *args, **kwargs):
        """
        Verify the 2FA code and complete the login process.
        
        Request Body:
        - code: The TOTP code entered by the user
        - user_id: The ID of the user trying to log in
        
        Returns:
        - 200 OK: {"success": true, "message": "Login successful", "user": {...}} if successful
        - 400 Bad Request: {"success": false, "message": "Error message"} if there's an error
        - 429 Too Many Requests: If rate limit is exceeded
        """
        try:
            # Debug the request data
            print("TwoFactorVerifyView - Request data:", request.data)
            
            # Validate request data
            serializer = TwoFactorVerifyRequestSerializer(data=request.data)
            if not serializer.is_valid():
                print("TwoFactorVerifyView - Serializer errors:", serializer.errors)
                return Response(
                    {
                        "success": False,
                        "message": "Invalid request data",
                        "errors": serializer.errors
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Get the validated data
            code = serializer.validated_data['code']
            user_id = serializer.validated_data['user_id']
            
            # Get the user
            try:
                user = User.objects.get(id=user_id)
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
                        "message": "Two-factor authentication is not enabled for this user."
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Decrypt the secret
            try:
                print(f"User {user.username} 2FA secret: {user_profile.totp_secret}")
                print(f"Secret type: {type(user_profile.totp_secret)}")
                
                # Check if the secret needs to be fixed
                if not user_profile.totp_secret:
                    return Response(
                        {
                            "success": False,
                            "message": "No 2FA secret found for this user."
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Try to fix the TOTP secret if needed
                fixed = check_and_fix_totp_secret(user_profile)
                if fixed:
                    print("TOTP secret was fixed, refreshing user profile")
                    user_profile.refresh_from_db()
                    print(f"Updated TOTP secret: {user_profile.totp_secret}")
                
                secret = decrypt_secret(user_profile.totp_secret)
                print(f"Successfully decrypted secret: {secret[:3]}...{secret[-3:]}")
            except Exception as e:
                print(f"Error decrypting 2FA secret: {str(e)}")
                return Response(
                    {
                        "success": False,
                        "message": f"Failed to decrypt 2FA secret: {str(e)}"
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
            # Verify the code
            if not verify_2fa_code(secret, code):
                # Try one more time with a different format of the secret
                print("First verification attempt failed, trying with alternative secret format")
                try:
                    import base64
                    # Try with base32 encoded secret
                    alt_secret = base64.b32encode(secret.encode()).decode()
                    print(f"Trying with alternative secret format: {alt_secret[:3]}...{alt_secret[-3:]}")
                    
                    if verify_2fa_code(alt_secret, code):
                        print("Verification successful with alternative secret format")
                    else:
                        print("Verification failed with alternative secret format")
                        return Response(
                            {
                                "success": False,
                                "message": "Invalid verification code"
                            },
                            status=status.HTTP_400_BAD_REQUEST
                        )
                except Exception as e:
                    print(f"Error trying alternative secret format: {str(e)}")
                    return Response(
                        {
                            "success": False,
                            "message": "Invalid verification code"
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )
            
            # Log the user in
            login(request, user)
            
            # Return the user profile data
            profile_serializer = UserProfileSerializer(user_profile)
            
            return Response(
                {
                    "success": True,
                    "message": "Login successful",
                    "user": profile_serializer.data
                },
                status=status.HTTP_200_OK
            )
            
        except Exception as e:
            return Response(
                {
                    "success": False,
                    "message": f"Failed to verify 2FA code: {str(e)}"
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class TwoFactorRecoveryVerifyView(APIView):
    """
    API endpoint to verify a recovery code during login.
    
    This view verifies the recovery code provided by the user during login,
    and if valid, completes the login process.
    
    Rate limiting is applied to prevent brute-force attacks:
    - 5 attempts per minute per IP address
    - 10 attempts per hour per user ID
    """
    permission_classes = [AllowAny]
    authentication_classes = [TemporaryTokenAuthentication]
    throttle_classes = [TwoFactorVerifyIPThrottle, TwoFactorVerifyUserThrottle]
    
    def post(self, request, *args, **kwargs):
        """
        Verify the recovery code and complete the login process.
        
        Request Body:
        - recovery_code: The recovery code entered by the user
        - user_id: The ID of the user trying to log in
        
        Returns:
        - 200 OK: {"success": true, "message": "Login successful", "user": {...}} if successful
        - 400 Bad Request: {"success": false, "message": "Error message"} if there's an error
        - 429 Too Many Requests: If rate limit is exceeded
        """
        serializer = TwoFactorRecoveryVerifyRequestSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                {
                    "success": False,
                    "message": "Invalid request data",
                    "errors": serializer.errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user_id = serializer.validated_data.get('user_id')
        recovery_code = serializer.validated_data.get('recovery_code')
        
        print(f"Received recovery code verification request for user_id: {user_id}")
        
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {
                    "success": False,
                    "message": "User not found"
                },
                status=status.HTTP_404_NOT_FOUND
            )
        
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
        
        # Check if 2FA is enabled for the user
        if not user_profile.is_2fa_enabled:
            return Response(
                {
                    "success": False,
                    "message": "Two-factor authentication is not enabled for this user"
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Rate limiting to prevent brute force attacks
        cache_key = f"2fa_recovery_attempts_{user.id}"
        attempts = cache.get(cache_key, 0)
        
        if attempts >= 5:  # Maximum 5 attempts within the time window
            return Response(
                {
                    "success": False,
                    "message": "Too many verification attempts. Please try again later."
                },
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )
        
        # Increment the attempts counter
        cache.set(cache_key, attempts + 1, 300)  # 5 minutes window
        
        print(f"User profile recovery_codes: {user_profile.recovery_codes}")
        print(f"Recovery code type: {type(user_profile.recovery_codes)}")
        
        # Check and fix recovery codes if needed
        fixed = check_and_fix_recovery_codes(user_profile)
        if fixed:
            print("Recovery codes were fixed, refreshing user profile")
            user_profile.refresh_from_db()
            print(f"Updated recovery_codes: {user_profile.recovery_codes}")
        
        # Decrypt and verify the recovery code
        try:
            if not user_profile.recovery_codes:
                print("No recovery codes available for this user")
                return Response(
                    {
                        "success": False,
                        "message": "No recovery codes are available for this user. Please contact support."
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            try:
                print(f"Attempting to decrypt recovery codes: {user_profile.recovery_codes[:20] if isinstance(user_profile.recovery_codes, str) else 'non-string'}...")
                stored_recovery_codes = decrypt_recovery_codes(user_profile.recovery_codes)
                print(f"Successfully decrypted recovery codes: {stored_recovery_codes}")
            except Exception as e:
                error_message = str(e)
                print(f"Error decrypting recovery codes: {error_message}")
                
                # Try one more time with a fresh fix attempt
                print("Attempting one more fix after decryption failure")
                if check_and_fix_recovery_codes(user_profile):
                    user_profile.refresh_from_db()
                    try:
                        stored_recovery_codes = decrypt_recovery_codes(user_profile.recovery_codes)
                        print("Successfully decrypted recovery codes after second fix attempt")
                    except Exception as e2:
                        print(f"Still failed to decrypt after second fix: {str(e2)}")
                        return Response(
                            {
                                "success": False,
                                "message": "Unable to verify recovery codes. Please contact support."
                            },
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR
                        )
                else:
                    return Response(
                        {
                            "success": False,
                            "message": "Failed to decrypt recovery codes. Please contact support."
                        },
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )
            
            # Check if the provided recovery code matches any of the stored codes
            if recovery_code not in stored_recovery_codes:
                print(f"Invalid recovery code: {recovery_code}")
                return Response(
                    {
                        "success": False,
                        "message": "Invalid recovery code"
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            print(f"Valid recovery code found: {recovery_code}")
            
            # Remove the used recovery code
            stored_recovery_codes.remove(recovery_code)
            
            # Re-encrypt and save the remaining recovery codes
            try:
                user_profile.recovery_codes = encrypt_recovery_codes(stored_recovery_codes)
                user_profile.save()
                print("Successfully updated recovery codes")
            except Exception as e:
                print(f"Error re-encrypting recovery codes: {str(e)}")
                # Still allow login but log the error
                # We won't mark the recovery code as used in this case
            
        except Exception as e:
            error_message = str(e)
            print(f"Unexpected error in recovery code verification: {error_message}")
            return Response(
                {
                    "success": False,
                    "message": f"Failed to verify recovery code: {error_message}"
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        # Log the user in
        login(request, user)
        
        # Return the user profile data
        profile_serializer = UserProfileSerializer(user_profile)
        
        return Response(
            {
                "success": True,
                "message": "Login successful using recovery code",
                "user": profile_serializer.data
            },
            status=status.HTTP_200_OK
        )
