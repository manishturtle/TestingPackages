"""
Custom authentication classes for the authentication app.
"""
from rest_framework import authentication
from rest_framework import exceptions
from django.contrib.auth.models import User


class TemporaryTokenAuthentication(authentication.BaseAuthentication):
    """
    Custom authentication class for temporary tokens used during 2FA verification.
    
    This authentication scheme accepts either:
    1. A user_id in the request body (for 2FA verification)
    2. A token in the Authorization header (for 2FA setup)
    
    It's specifically designed for the intermediate steps in the 2FA flow.
    """
    
    def authenticate(self, request):
        """
        Authenticate the request based on user_id in the request body
        or token in the Authorization header.
        
        Args:
            request: The request object
            
        Returns:
            tuple: (user, None) if authentication is successful
            
        Raises:
            AuthenticationFailed: If authentication fails
        """
        # First try to authenticate with token in the Authorization header
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if auth_header.startswith('Bearer '):
            token_key = auth_header.split(' ')[1]
            
            from rest_framework.authtoken.models import Token
            
            try:
                token = Token.objects.get(key=token_key)
                return (token.user, token)
            except Token.DoesNotExist:
                pass  # Continue to try other authentication methods
            except Exception as e:
                print(f"Token authentication error: {str(e)}")
        
        # If token authentication failed, try with user_id
        user_id = None
        
        # Check request data for user_id
        if hasattr(request, 'data') and isinstance(request.data, dict):
            user_id = request.data.get('user_id')
        
        # Also check query parameters for user_id
        if not user_id and request.method == 'GET':
            user_id = request.query_params.get('user_id')
            
        # Check for temp_token in query parameters
        temp_token = None
        if request.method == 'GET':
            temp_token = request.query_params.get('temp_token')
            if temp_token:
                from rest_framework.authtoken.models import Token
                try:
                    token = Token.objects.get(key=temp_token)
                    return (token.user, token)
                except Token.DoesNotExist:
                    pass  # Continue to try other authentication methods
                except Exception as e:
                    print(f"Temp token authentication error: {str(e)}")
        
        if not user_id:
            # No user_id provided, return None to allow other
            # authentication methods to be attempted
            return None
        
        try:
            # Try to get the user with the provided ID
            user = User.objects.get(id=user_id)
            
            # Return the user and None as the auth token
            return (user, None)
            
        except User.DoesNotExist:
            # User with this ID does not exist
            raise exceptions.AuthenticationFailed('Invalid user ID')
        except Exception as e:
            # Some other error occurred
            raise exceptions.AuthenticationFailed(f'Authentication error: {str(e)}')
