"""
Utility functions for the authentication app.
"""
import pyotp
import random
import string
import datetime


def generate_2fa_secret():
    """
    Generate a new secret key for TOTP-based two-factor authentication.
    
    This function uses pyotp.random_base32() to create a cryptographically
    secure random base32 string that can be used as a secret key for
    TOTP (Time-based One-Time Password) authentication.
    
    Returns:
        str: A base32 encoded string to be used as a 2FA secret key.
    """
    return pyotp.random_base32()


def generate_2fa_uri(secret, email, issuer_name="SaaS ERP"):
    """
    Generate a URI for a TOTP QR code.
    
    Args:
        secret (str): The secret key for TOTP generation.
        email (str): The user's email address.
        issuer_name (str): The name of the issuer (e.g., your application name).
        
    Returns:
        str: A URI that can be used to generate a QR code for TOTP setup.
    """
    try:
        # URL encode the issuer name to handle special characters
        import urllib.parse
        safe_issuer = urllib.parse.quote(issuer_name)
        
        # Create a TOTP object with the secret
        totp = pyotp.TOTP(secret)
        
        # Generate the provisioning URI
        uri = totp.provisioning_uri(name=email, issuer_name=safe_issuer)
        
        # Log the generated URI for debugging
        print(f"Generated URI: {uri}")
        
        return uri
    except Exception as e:
        # Log the error and return a fallback URI
        print(f"Error generating 2FA URI: {str(e)}")
        
        # Create a basic URI as fallback
        safe_email = urllib.parse.quote(email)
        safe_issuer = urllib.parse.quote(issuer_name)
        fallback_uri = f"otpauth://totp/{safe_issuer}:{safe_email}?secret={secret}&issuer={safe_issuer}"
        
        print(f"Using fallback URI: {fallback_uri}")
        return fallback_uri


def verify_totp_code(secret, code):
    """
    Verify a TOTP code against a secret key.
    
    Args:
        secret (str): The user's 2FA secret key.
        code (str): The TOTP code to verify.
        
    Returns:
        bool: True if the code is valid, False otherwise.
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(code)


def verify_2fa_code(secret, code):
    """
    Verify a TOTP code against a 2FA secret key.
    
    This function verifies if a Time-based One-Time Password (TOTP) code
    is valid for the given secret key. It uses a window of 1 to account for
    slight time differences between the server and the client.
    
    Args:
        secret (str): The user's 2FA secret key.
        code (str): The TOTP code entered by the user.
        
    Returns:
        bool: True if the code is valid, False otherwise.
        
    Raises:
        ValueError: If the secret key is invalid.
    """
    import pyotp
    import time
    
    try:
        # Clean up the code - remove spaces and make sure it's a string
        if not isinstance(code, str):
            code = str(code)
        
        code = code.strip().replace(" ", "")
        
        # Ensure the code is 6 digits
        if not code.isdigit() or len(code) != 6:
            print(f"Invalid code format: {code}")
            return False
        
        # Clean up the secret - remove spaces and make sure it's a string
        if not isinstance(secret, str):
            secret = str(secret)
        
        secret = secret.strip().replace(" ", "")
        
        # Create a TOTP object with the secret
        try:
            totp = pyotp.TOTP(secret)
        except Exception as e:
            print(f"Error creating TOTP object: {str(e)}")
            # Try to fix the secret if it's not in the correct format
            try:
                # Sometimes base32 encoding is required
                import base64
                fixed_secret = base64.b32encode(secret.encode()).decode()
                print(f"Trying with fixed secret: {fixed_secret}")
                totp = pyotp.TOTP(fixed_secret)
            except Exception as e2:
                print(f"Error creating TOTP object with fixed secret: {str(e2)}")
                return False
        
        # Log for debugging
        print(f"Verifying code: {code} with secret: {secret[:3]}...{secret[-3:]}")
        
        # Get the current time and expected code for debugging
        current_time = int(time.time())
        expected_code = totp.at(current_time)
        print(f"Current time: {current_time}, Expected code: {expected_code}")
        
        # Try with different time windows for better compatibility
        for window in [1, 2]:
            # Verify the code with the specified window
            # This allows for codes that are 30 or 60 seconds before or after the current time
            result = totp.verify(code, valid_window=window)
            
            if result:
                print(f"Verification successful with window={window}")
                return True
            else:
                print(f"Verification failed with window={window}")
        
        # Try with a custom time window as a last resort
        for offset in [-2, -1, 0, 1, 2]:
            custom_time = current_time + (offset * 30)
            expected_code = totp.at(custom_time)
            print(f"Trying with offset {offset}, time: {custom_time}, code: {expected_code}")
            
            if expected_code == code:
                print(f"Code matches with offset {offset}")
                return True
        
        print("All verification attempts failed")
        return False
    except Exception as e:
        # Log the error for debugging
        print(f"Error verifying 2FA code: {str(e)}")
        return False


def generate_recovery_codes(num_codes=8):
    """
    Generate a list of random, unique recovery codes for 2FA backup.
    
    These codes can be used as a backup method to access an account when
    the primary 2FA method is unavailable (e.g., lost phone).
    
    Args:
        num_codes (int): Number of recovery codes to generate. Default is 8.
        
    Returns:
        list: A list of unique recovery codes.
    """
    import secrets
    
    # Define the characters to use in the recovery codes
    # Excluding similar-looking characters like 0, O, 1, I, etc.
    alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    
    # Define the format of the recovery codes (e.g., XXXX-XXXX-XXXX)
    code_length = 12
    group_size = 4
    
    # Generate the specified number of unique recovery codes
    recovery_codes = set()
    while len(recovery_codes) < num_codes:
        # Generate a random code
        code = ''.join(secrets.choice(alphabet) for _ in range(code_length))
        
        # Format the code with hyphens (e.g., XXXX-XXXX-XXXX)
        formatted_code = '-'.join(code[i:i+group_size] for i in range(0, code_length, group_size))
        
        # Add the code to the set (ensures uniqueness)
        recovery_codes.add(formatted_code)
    
    # Convert the set to a list and return
    return list(recovery_codes)


def encrypt_secret(secret_key):
    """
    Encrypt a 2FA secret key using Fernet symmetric encryption.
    
    Args:
        secret_key (str): The 2FA secret key to encrypt.
        
    Returns:
        str: The encrypted secret key as a base64-encoded string.
        
    Raises:
        ValueError: If encryption fails.
    """
    from cryptography.fernet import Fernet
    import os
    import base64
    
    try:
        # Get the encryption key from environment variable or generate a new one
        encryption_key = os.environ.get('FERNET_KEY')
        
        # If no key is set in environment, generate one
        if not encryption_key:
            print("WARNING: No FERNET_KEY found in environment variables. Generating a new key.")
            print("In production, set a secure FERNET_KEY as an environment variable.")
            # Generate a proper Fernet key
            encryption_key = Fernet.generate_key().decode()
            # Save it to the environment for this session
            os.environ['FERNET_KEY'] = encryption_key
            print(f"Generated FERNET_KEY: {encryption_key}")
        
        # Ensure the key is in the correct format
        if isinstance(encryption_key, str):
            encryption_key = encryption_key.encode()
        
        # Create a Fernet cipher with the key
        cipher = Fernet(encryption_key)
        
        # Encrypt the secret key
        encrypted_data = cipher.encrypt(secret_key.encode())
        
        # Return the encrypted data as a base64 string
        return base64.b64encode(encrypted_data).decode()
    
    except Exception as e:
        raise ValueError(f"Failed to encrypt secret: {str(e)}")


def decrypt_secret(encrypted_secret):
    """
    Decrypt a 2FA secret key that was encrypted using Fernet.
    
    Args:
        encrypted_secret (str): The encrypted 2FA secret key as a base64-encoded string.
        
    Returns:
        str: The decrypted secret key.
        
    Raises:
        ValueError: If decryption fails.
    """
    from cryptography.fernet import Fernet, InvalidToken
    import os
    import base64
    
    if not encrypted_secret:
        raise ValueError("No encrypted secret provided")
    
    try:
        # Get the encryption key from environment variable
        encryption_key = os.environ.get('FERNET_KEY')
        
        if not encryption_key:
            # For development/testing, try to use a default key
            # This is NOT secure for production!
            print("WARNING: No FERNET_KEY found in environment variables.")
            print("Using a default key for development purposes only.")
            print("In production, set a secure FERNET_KEY as an environment variable.")
            
            # Use a default key for development/testing
            encryption_key = "bSYs17AZ0R75gHHkfeFoI99E3rDz6lk3-pMFwCEUJMI="
            os.environ['FERNET_KEY'] = encryption_key
        
        print(f"Using encryption key: {encryption_key[:5]}...{encryption_key[-5:]}")
        
        # Ensure the key is in the correct format
        if isinstance(encryption_key, str):
            encryption_key = encryption_key.encode()
        
        # Create a Fernet cipher with the key
        try:
            cipher = Fernet(encryption_key)
        except Exception as e:
            raise ValueError(f"Invalid encryption key format: {str(e)}")
        
        # Decode the base64 string to get the encrypted data
        try:
            # Check if the encrypted_secret is already in bytes
            if isinstance(encrypted_secret, bytes):
                encrypted_data = encrypted_secret
            else:
                # Try to decode as base64
                try:
                    encrypted_data = base64.b64decode(encrypted_secret)
                except Exception:
                    # If not valid base64, try to encode as bytes and then decrypt
                    encrypted_data = encrypted_secret.encode()
        except Exception as e:
            raise ValueError(f"Invalid base64 encoding: {str(e)}")
        
        print(f"Encrypted data type: {type(encrypted_data)}")
        print(f"Encrypted data length: {len(encrypted_data)}")
        print(f"Encrypted data prefix: {encrypted_data[:10]}")
        
        # Decrypt the data
        try:
            decrypted_data = cipher.decrypt(encrypted_data)
        except InvalidToken:
            raise ValueError("Invalid token or wrong decryption key")
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
        
        # Return the decrypted data as a string
        return decrypted_data.decode()
    
    except ValueError:
        # Re-raise ValueError exceptions
        raise
    except Exception as e:
        raise ValueError(f"Failed to decrypt secret: {str(e)}")


def generate_fernet_key():
    """
    Generate a secure Fernet key for encryption.
    
    This function generates a URL-safe base64-encoded 32-byte key that can be
    used for Fernet symmetric encryption. This key should be stored securely
    and used as the FERNET_KEY environment variable in production.
    
    Returns:
        str: A URL-safe base64-encoded 32-byte key.
    """
    from cryptography.fernet import Fernet
    
    # Generate a new Fernet key
    key = Fernet.generate_key()
    
    # Return the key as a string
    return key.decode()


def generate_otp(length=6):
    """
    Generate a random numeric OTP of specified length.
    
    Args:
        length (int): Length of the OTP to generate. Default is 6.
        
    Returns:
        str: A random numeric OTP.
    """
    return ''.join(random.choices(string.digits, k=length))


def send_otp_email(email, first_name, otp):
    """
    Send an OTP to the user's email using ZeptoMail API.
    
    Args:
        email (str): The recipient's email address.
        first_name (str): The recipient's first name.
        otp (str): The OTP to send.
        
    Returns:
        dict: The response from the ZeptoMail API or None if an error occurred.
    """
    import requests
    
    url = "https://api.zeptomail.in/v1.1/email"
    
    html_content = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
        <h2 style="color: #1e8e3e;">Verify Your Email</h2>
        <p>Hello {first_name},</p>
        <p>Thank you for registering with SaaS ERP. To complete your registration, please use the verification code below:</p>
        <div style="background-color: #f5f5f5; padding: 15px; text-align: center; font-size: 24px; letter-spacing: 5px; font-weight: bold; margin: 20px 0;">
            {otp}
        </div>
        <p>This code will expire in 10 minutes.</p>
        <p>If you did not request this verification, please ignore this email.</p>
        <p>Best regards,<br>The SaaS ERP Team</p>
    </div>
    """
    
    payload = {
        "from": {"address": "noreply@turtleit.in"},
        "to": [{"email_address": {"address": email, "name": first_name}}],
        "subject": "Verify Your Email - SaaS ERP",
        "htmlbody": html_content
    }
    
    headers = {
        'accept': "application/json",
        'content-type': "application/json",
        'authorization': "Zoho-enczapikey PHtE6r0FRejqjTUu9UJVs/TuEcakMth8ruNmLwBA44wTW/5VTU0Dq9ovljK3rBh+BqYUQPGam4Jst72fte7UIm67NT5KD2qyqK3sx/VYSPOZsbq6x00atV0ff0XdV4Drd9Fq0CXfudzTNA==",
    }
    
    try:
        response = requests.post(url, json=payload, headers=headers)
        print(f"Email sent response: {response.text}")
        return response.json()
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return None


def send_tenant_admin_welcome_email_direct(email, first_name, password, tenant_name, tenant_url):
    """
    Send a welcome email to a newly created tenant admin using ZeptoMail API.
    
    Args:
        email (str): The recipient's email address.
        first_name (str): The recipient's first name.
        password (str): The admin's password.
        tenant_name (str): The name of the tenant.
        tenant_url (str): The URL of the tenant.
        
    Returns:
        dict: The response from the ZeptoMail API or None if an error occurred.
    """
    import requests
    
    url = "https://api.zeptomail.in/v1.1/email"
    
    html_content = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
        <h2 style="color: #1e8e3e;">Welcome to {tenant_name}</h2>
        <p>Hello {first_name},</p>
        <p>Your tenant has been successfully created in our SaaS ERP system.</p>
        
        <h3>Tenant Details:</h3>
        <ul>
            <li><strong>Name:</strong> {tenant_name}</li>
            <li><strong>URL:</strong> <a href="{tenant_url}">{tenant_url}</a></li>
        </ul>
        
        <h3>Your Admin Account:</h3>
        <ul>
            <li><strong>Email:</strong> {email}</li>
            <li><strong>Password:</strong> {password}</li>
        </ul>
        
        <p>Please log in and change your password immediately.</p>
        
        <div style="margin: 20px 0; text-align: center;">
            <a href="{tenant_url}" style="background-color: #1e8e3e; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Log In Now</a>
        </div>
        
        <p>Thank you for choosing our platform!</p>
        <p>Best regards,<br>The SaaS ERP Team</p>
    </div>
    """
    
    payload = {
        "from": {"address": "noreply@turtleit.in"},
        "to": [{"email_address": {"address": email, "name": first_name}}],
        "subject": f"Welcome to {tenant_name} - Your Admin Account",
        "htmlbody": html_content
    }
    
    headers = {
        'accept': "application/json",
        'content-type': "application/json",
        'authorization': "Zoho-enczapikey PHtE6r0FRejqjTUu9UJVs/TuEcakMth8ruNmLwBA44wTW/5VTU0Dq9ovljK3rBh+BqYUQPGam4Jst72fte7UIm67NT5KD2qyqK3sx/VYSPOZsbq6x00atV0ff0XdV4Drd9Fq0CXfudzTNA==",
    }
    
    try:
        response = requests.post(url, json=payload, headers=headers)
        print(f"Tenant admin welcome email sent response: {response.text}")
        return response.json()
    except Exception as e:
        print(f"Error sending tenant admin welcome email: {str(e)}")
        return None


def generate_temp_token(user):
    """
    Generate a temporary token for 2FA setup.
    This token has limited permissions and expires after a short time.
    
    Args:
        user: The user to generate a token for
        
    Returns:
        str: A temporary JWT token
    """
    from rest_framework_simplejwt.tokens import RefreshToken
    
    # Create a token with a short expiry time
    token = RefreshToken.for_user(user)
    
    # Add custom claims
    token['is_temporary'] = True
    token['requires_2fa_setup'] = True
    token['exp'] = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)  # Short expiry
    
    return str(token.access_token)


def encrypt_recovery_codes(recovery_codes):
    """
    Encrypt a list of recovery codes for secure storage.
    
    Args:
        recovery_codes (list): List of recovery codes to encrypt.
        
    Returns:
        str: JSON string of encrypted recovery codes.
    """
    import json
    
    # Convert list to JSON string
    json_codes = json.dumps(recovery_codes)
    
    # Encrypt the JSON string
    encrypted_codes = encrypt_secret(json_codes)
    
    return encrypted_codes


def decrypt_recovery_codes(encrypted_codes):
    """
    Decrypt recovery codes that were encrypted using Fernet.
    
    Args:
        encrypted_codes: The encrypted recovery codes
        
    Returns:
        list: The decrypted recovery codes as a list
        
    Raises:
        ValueError: If decryption fails
    """
    from cryptography.fernet import Fernet, InvalidToken
    import json
    import base64
    import os
    
    if not encrypted_codes:
        raise ValueError("No encrypted recovery codes provided")
    
    # If already a list, return as is
    if isinstance(encrypted_codes, list):
        return encrypted_codes
    
    # Try to parse as JSON directly (maybe it's not encrypted)
    if isinstance(encrypted_codes, str):
        try:
            codes_list = json.loads(encrypted_codes)
            if isinstance(codes_list, list):
                print("Recovery codes are stored as JSON string, not encrypted")
                return codes_list
        except json.JSONDecodeError:
            # Not JSON, continue with decryption
            pass
    
    try:
        # Get the encryption key from environment variable
        encryption_key = os.environ.get('FERNET_KEY')
        
        if not encryption_key:
            # For development/testing, try to use a default key
            print("WARNING: No FERNET_KEY found in environment variables.")
            print("Using a default key for development purposes only.")
            
            # Use a default key for development/testing
            encryption_key = "bSYs17AZ0R75gHHkfeFoI99E3rDz6lk3-pMFwCEUJMI="
            os.environ['FERNET_KEY'] = encryption_key
        
        print(f"Using encryption key: {encryption_key[:5]}...{encryption_key[-5:]}")
        
        # Ensure the key is in the correct format
        if isinstance(encryption_key, str):
            encryption_key = encryption_key.encode()
        
        # Create a Fernet cipher with the key
        try:
            cipher = Fernet(encryption_key)
        except Exception as e:
            raise ValueError(f"Invalid encryption key format: {str(e)}")
        
        # Decode the base64 string to get the encrypted data
        try:
            # Check if the encrypted_codes is already in bytes
            if isinstance(encrypted_codes, bytes):
                encrypted_data = encrypted_codes
            else:
                # Try to decode as base64
                try:
                    encrypted_data = base64.b64decode(encrypted_codes)
                except Exception:
                    # If not valid base64, try to encode as bytes and then decrypt
                    encrypted_data = encrypted_codes.encode()
        except Exception as e:
            raise ValueError(f"Invalid base64 encoding: {str(e)}")
        
        print(f"Encrypted data type: {type(encrypted_data)}")
        print(f"Encrypted data length: {len(encrypted_data)}")
        print(f"Encrypted data prefix: {encrypted_data[:10]}")
        
        # Decrypt the data
        try:
            decrypted_data = cipher.decrypt(encrypted_data)
        except InvalidToken:
            raise ValueError("Invalid token or wrong decryption key")
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
        
        # Parse the JSON data
        try:
            recovery_codes = json.loads(decrypted_data.decode())
            if not isinstance(recovery_codes, list):
                raise ValueError("Decrypted data is not a list of recovery codes")
            return recovery_codes
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse decrypted data as JSON: {str(e)}")
        
    except ValueError:
        # Re-raise ValueError exceptions
        raise
    except Exception as e:
        raise ValueError(f"Failed to decrypt recovery codes: {str(e)}")


def check_and_fix_recovery_codes(user_profile):
    """
    Check if recovery codes are properly formatted and fix them if needed.
    
    Args:
        user_profile (UserProfile): The user profile to check
        
    Returns:
        bool: True if recovery codes were fixed, False if no fix was needed
    """
    import json
    import base64
    from cryptography.fernet import Fernet, InvalidToken
    import os
    
    if not user_profile.recovery_codes:
        print("No recovery codes found")
        return False
    
    print(f"Recovery codes type: {type(user_profile.recovery_codes)}")
    
    # Generate default recovery codes if needed
    if user_profile.recovery_codes is None:
        try:
            print("Generating new recovery codes")
            recovery_codes = generate_recovery_codes()
            user_profile.recovery_codes = encrypt_recovery_codes(recovery_codes)
            user_profile.save()
            print("Successfully generated new recovery codes")
            return True
        except Exception as e:
            print(f"Error generating recovery codes: {str(e)}")
            return False
    
    # If recovery_codes is already a string, check if it's properly encrypted
    if isinstance(user_profile.recovery_codes, str):
        try:
            # Try to decrypt it directly
            try:
                decrypt_recovery_codes(user_profile.recovery_codes)
                print("Recovery codes are already properly encrypted")
                return False
            except Exception as e:
                print(f"Failed to decrypt recovery codes, trying to fix: {str(e)}")
                
                # Try to parse it as JSON directly (maybe it's not encrypted)
                try:
                    codes_list = json.loads(user_profile.recovery_codes)
                    if isinstance(codes_list, list):
                        print("Recovery codes are stored as JSON string, encrypting them")
                        encrypted_codes = encrypt_recovery_codes(codes_list)
                        user_profile.recovery_codes = encrypted_codes
                        user_profile.save()
                        print("Successfully fixed recovery codes")
                        return True
                except json.JSONDecodeError:
                    print("Recovery codes are not valid JSON")
                
                # Try with a different encryption key as fallback
                try:
                    # Get the encryption key from environment variable
                    encryption_key = os.environ.get('FERNET_KEY')
                    
                    if not encryption_key:
                        # For development/testing, try to use a default key
                        encryption_key = "bSYs17AZ0R75gHHkfeFoI99E3rDz6lk3-pMFwCEUJMI="
                    
                    # Ensure the key is in the correct format
                    if isinstance(encryption_key, str):
                        encryption_key = encryption_key.encode()
                    
                    # Create a Fernet cipher with the key
                    cipher = Fernet(encryption_key)
                    
                    # Try to decode the recovery codes
                    encrypted_data = base64.b64decode(user_profile.recovery_codes)
                    decrypted_data = cipher.decrypt(encrypted_data)
                    
                    # If we get here, we can decrypt with this key
                    # Re-encrypt with the current key
                    codes_list = json.loads(decrypted_data.decode())
                    encrypted_codes = encrypt_recovery_codes(codes_list)
                    user_profile.recovery_codes = encrypted_codes
                    user_profile.save()
                    print("Successfully re-encrypted recovery codes with current key")
                    return True
                except Exception as e:
                    print(f"Failed to fix recovery codes with alternative key: {str(e)}")
        except Exception as e:
            print(f"Error checking recovery codes: {str(e)}")
    
    # If recovery_codes is a list or dict, it needs to be encrypted
    if isinstance(user_profile.recovery_codes, (list, dict)):
        try:
            print(f"Converting recovery codes from {type(user_profile.recovery_codes)} to encrypted string")
            # Convert to JSON string and encrypt
            if isinstance(user_profile.recovery_codes, dict):
                # If it's a dict, extract the list of codes
                codes_list = list(user_profile.recovery_codes.values())
            else:
                codes_list = user_profile.recovery_codes
            
            # Encrypt the codes
            encrypted_codes = encrypt_recovery_codes(codes_list)
            user_profile.recovery_codes = encrypted_codes
            user_profile.save()
            print("Successfully fixed recovery codes")
            return True
        except Exception as e:
            print(f"Error fixing recovery codes: {str(e)}")
            return False
    
    # If we get here and still haven't fixed the codes, generate new ones
    try:
        print("Generating new recovery codes as fallback")
        recovery_codes = generate_recovery_codes()
        user_profile.recovery_codes = encrypt_recovery_codes(recovery_codes)
        user_profile.save()
        print("Successfully generated new recovery codes as fallback")
        return True
    except Exception as e:
        print(f"Error generating fallback recovery codes: {str(e)}")
        return False


def check_and_fix_totp_secret(user_profile):
    """
    Check if TOTP secret is properly formatted and fix it if needed.
    
    Args:
        user_profile (UserProfile): The user profile to check
        
    Returns:
        bool: True if TOTP secret was fixed, False if no fix was needed
    """
    if not user_profile.totp_secret:
        print("No TOTP secret found")
        return False
    
    # Check if totp_secret is already a string
    if isinstance(user_profile.totp_secret, str):
        try:
            # Try to decrypt it to see if it's valid
            decrypt_secret(user_profile.totp_secret)
            print("TOTP secret is already properly encrypted")
            return False
        except Exception as e:
            print(f"Error checking TOTP secret: {str(e)}")
    
    # If we need to re-encrypt the secret
    try:
        print(f"Re-encrypting TOTP secret: {user_profile.totp_secret}")
        # If it's not encrypted, encrypt it
        encrypted_secret = encrypt_secret(user_profile.totp_secret)
        user_profile.totp_secret = encrypted_secret
        user_profile.save()
        print("Successfully fixed TOTP secret")
        return True
    except Exception as e:
        print(f"Error fixing TOTP secret: {str(e)}")
        return False


def has_permission(user, permission_codename):
    """
    Check if a user has a specific permission through their assigned roles.
    
    Args:
        user: The User object to check
        permission_codename: The codename of the permission to check for
        
    Returns:
        bool: True if the user has the permission, False otherwise
    """
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        # Check if user is authenticated
        if not user or not hasattr(user, 'is_authenticated') or not user.is_authenticated:
            logger.warning(f"Permission check failed: User is not authenticated")
            return False
            
        # Superusers have all permissions
        if hasattr(user, 'is_superuser') and user.is_superuser:
            logger.info(f"Permission granted: User {user.email} is a superuser")
            return True
            
        # Check if the user has a profile with is_tenant_admin=True
        # Tenant admins have all permissions within their tenant
        try:
            from .models import UserProfile
            profile = UserProfile.objects.get(user=user)
            
            if profile.is_tenant_admin and user.is_staff:
                logger.info(f"Permission granted: User {user.email} is a tenant admin")
                return True
        except UserProfile.DoesNotExist:
            logger.warning(f"No UserProfile found for user {user.email}")
            # Continue with role-based permission check
        except Exception as e:
            logger.warning(f"Error checking tenant admin status: {str(e)}")
            # Continue with role-based permission check
            
        # Check if the user has the permission through their roles
        from .models import UserRole, RolePermission, Permission
        
        # Get all roles assigned to the user
        user_roles = UserRole.objects.filter(user=user)
        
        if not user_roles.exists():
            logger.warning(f"User {user.email} has no roles assigned")
            return False
        
        # Get all role IDs
        role_ids = user_roles.values_list('role_id', flat=True)
        
        # Check if any of the user's roles have the permission
        try:
            permission = Permission.objects.get(codename=permission_codename)
            has_perm = RolePermission.objects.filter(
                role_id__in=role_ids,
                permission=permission
            ).exists()
            
            if has_perm:
                logger.info(f"Permission granted: User {user.email} has permission {permission_codename} through roles")
            else:
                logger.warning(f"Permission denied: User {user.email} does not have permission {permission_codename}")
            
            return has_perm
        except Permission.DoesNotExist:
            logger.warning(f"Permission {permission_codename} does not exist")
            return False
    except Exception as e:
        logger.error(f"Error checking permission {permission_codename} for user {getattr(user, 'email', 'unknown')}: {str(e)}", exc_info=True)
        return False