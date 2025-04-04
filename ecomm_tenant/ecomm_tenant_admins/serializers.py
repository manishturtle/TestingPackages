# --- serializers.py ---

from rest_framework import serializers
from ecomm_superadmin.models import User, Tenant, SubscriptionPlan # Assuming 'User' here is the base user model
from ecomm_tenant.ecomm_tenant_admins.models import ( # Adjust imports as per your project structure
    UserProfile,
    PendingRegistration,
    Role,
    Permission,
    UserRole,
    RolePermission,
    Company,
    TenantUser # Assuming TenantUser is your tenant-specific user model
)
from django.contrib.auth.hashers import make_password
from django.utils import timezone # Needed for setting timestamps
import secrets # Needed for password generation
import string  # Needed for password generation
import re      # Needed for schema name generation

# Base User Serializer (Used by others)
class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for the base User model.
    """
    profile = serializers.SerializerMethodField()

    class Meta:
        model = User # Use your base User model
        fields = ('id', 'username', 'email', 'first_name', 'last_name', 'is_active', 'date_joined', 'profile')
        read_only_fields = ('id', 'date_joined')

    def get_profile(self, obj):
        """
        Get the user profile data. Handles potential UserProfile.DoesNotExist.
        """
        try:
            # Assuming UserProfile has a OneToOneField to the base User model
            profile = UserProfile.objects.get(user_id=obj.id)
            return {
                'is_company_admin': profile.is_company_admin,
                'is_tenant_admin': profile.is_tenant_admin,
                'nationality': profile.nationality,
                'is_email_verified': profile.is_email_verified,
                'is_2fa_enabled': profile.is_2fa_enabled,
                'needs_2fa_setup': profile.needs_2fa_setup,
                'company_id': profile.company_id # Include company_id if relevant
            }
        except UserProfile.DoesNotExist:
            return None
        except AttributeError: # Handle case where profile might be None unexpectedly
             return None

# Email Check Serializer
class EmailCheckSerializer(serializers.Serializer):
    """
    Serializer for checking email availability during signup.
    """
    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        """
        Validate that the email is in a valid format and normalize.
        """
        return value.lower()  # Normalize to lowercase

# User Registration Serializer (Creates Base User and Profile)
class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration (likely for the initial superadmin/company admin).
    Creates both User and UserProfile.
    """
    first_name = serializers.CharField(write_only=True, required=True)
    last_name = serializers.CharField(write_only=True, required=True)
    nationality = serializers.CharField(write_only=True, required=False, allow_blank=True, allow_null=True)
    password = serializers.CharField(write_only=True, required=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User # Use your base User model
        fields = ('id', 'email', 'username', 'first_name', 'last_name', 'nationality', 'password', 'password_confirm')
        extra_kwargs = {
            'email': {'required': True},
            'username': {'required': False} # Username optional, defaults to email
        }

    def validate_email(self, value):
        """
        Validate that the email is unique in the base User table.
        """
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("Email already registered.")
        return value.lower()

    def validate(self, data):
        """
        Validate that the passwords match and set username if not provided.
        """
        if data.get('password') != data.get('password_confirm'):
            raise serializers.ValidationError({"password_confirm": "Passwords do not match."})

        # Use email as username if not provided
        if not data.get('username'):
            data['username'] = data.get('email')

        return data

    def create(self, validated_data):
        """
        Create and return a new base user with encrypted password and user profile.
        """
        first_name = validated_data.pop('first_name')
        last_name = validated_data.pop('last_name')
        nationality = validated_data.pop('nationality', None)
        validated_data.pop('password_confirm')

        # Create the base user
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=first_name,
            last_name=last_name
        )

        # Create the associated user profile
        # Note: Assumes this registration is for a Company Admin initially
        UserProfile.objects.create(
            user=user,
            nationality=nationality,
            is_company_admin=True, # Adjust based on registration context
            is_tenant_admin=False, # Adjust based on registration context
            is_email_verified=False, # Usually requires email confirmation step
            created_at=timezone.now(),
            updated_at=timezone.now(),
            # company_id might be set later or based on context
        )

        return user

# Pending Registration Serializer
class PendingRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for pending user registration (e.g., requiring OTP verification).
    """
    password = serializers.CharField(write_only=True, required=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = PendingRegistration
        fields = ('id', 'email', 'first_name', 'last_name', 'nationality', 'password', 'password_confirm', 'otp')
        read_only_fields = ('id', 'otp')
        extra_kwargs = {
            'email': {'required': True},
        }

    def validate_email(self, value):
        """
        Validate that the email isn't already in the main User table.
        """
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("Email already registered.")
        return value.lower()

    def validate(self, data):
        """
        Validate that the passwords match.
        """
        if data.get('password') != data.get('password_confirm'):
            raise serializers.ValidationError({"password_confirm": "Passwords do not match."})
        return data

    def create(self, validated_data):
        """
        Create and return a new pending registration.
        """
        validated_data.pop('password_confirm', None)
        # Password in PendingRegistration should likely be stored hashed
        validated_data['password'] = make_password(validated_data['password'])
        return PendingRegistration.objects.create(**validated_data)

# Company Serializer
class CompanySerializer(serializers.ModelSerializer):
    """
    Serializer for the Company model (if used distinctly from Client/Tenant).
    """
    class Meta:
        model = Company
        fields = ('id', 'name', 'industry', 'size', 'country', 'created_at', 'updated_at')
        read_only_fields = ('id', 'created_at', 'updated_at')

# Subscription Plan Serializer
class SubscriptionPlanSerializer(serializers.ModelSerializer):
    """
    Serializer for SubscriptionPlan model.
    """
    class Meta:
        model = SubscriptionPlan
        fields = ('id', 'name', 'description', 'price', 'max_users', 'max_storage',
                  'features', 'is_active', 'created_at', 'updated_at')
        read_only_fields = ('id', 'created_at', 'updated_at')

# Tenant (Client) Serializer
class TenantSerializer(serializers.ModelSerializer):
    """
    Serializer for Tenant model (tenants). Handles creation of initial tenant admin.
    """
    subscription_plan = SubscriptionPlanSerializer(read_only=True)
    subscription_plan_id = serializers.PrimaryKeyRelatedField(
        queryset=SubscriptionPlan.objects.all(),
        source='subscription_plan',
        write_only=True,
        required=False,
        allow_null=True
    )

    # Fields for initial tenant admin user (write-only)
    admin_email = serializers.EmailField(write_only=True, required=False)
    admin_first_name = serializers.CharField(max_length=255, write_only=True, required=False)
    admin_last_name = serializers.CharField(max_length=255, write_only=True, required=False)
    admin_password = serializers.CharField(max_length=255, write_only=True, required=False)

    class Meta:
        model = Tenant
        fields = (
            'id', 'name', 'description', 'schema_name', 'url_suffix',
            'status', 'environment', 'on_trial', 'trial_end_date', 'paid_until',
            'subscription_plan', 'subscription_plan_id',
            'created_at', 'updated_at', 'admin_email', 'admin_first_name',
            'admin_last_name', 'admin_password'
        )
        read_only_fields = ('id', 'schema_name', 'created_at', 'updated_at')

    def validate_url_suffix(self, value):
        """
        Validate that the url_suffix is unique and contains only valid characters.
        """
        if value is None:
            return value

        # Check uniqueness (case-insensitive), excluding self during update
        query = Tenant.objects.filter(url_suffix__iexact=value)
        if self.instance:
            query = query.exclude(pk=self.instance.pk)
        if query.exists():
            raise serializers.ValidationError("This URL suffix is already in use.")

        return value

    def create(self, validated_data):
        """
        Create and return a new Tenant instance. Auto-generate schema_name.
        Create initial tenant admin user and profile within the tenant schema.
        """
        # Generate schema_name if not provided
        if 'schema_name' not in validated_data:
            base_schema_name = re.sub(r'[^\w]', '', validated_data['name'].lower().replace(' ', '_'))
            schema_name = base_schema_name
            counter = 1
            while Tenant.objects.filter(schema_name=schema_name).exists():
                schema_name = f"{base_schema_name}_{counter}"
                counter += 1
            validated_data['schema_name'] = schema_name

        # Extract admin user data
        admin_email = validated_data.pop('admin_email', None)
        admin_first_name = validated_data.pop('admin_first_name', None)
        admin_last_name = validated_data.pop('admin_last_name', None)
        admin_password = validated_data.pop('admin_password', None)

        # Create the tenant
        tenant = Tenant.objects.create(**validated_data)

        # Create admin user if all required fields are provided
        if admin_email and admin_first_name and admin_last_name and admin_password:
            from django.db import connection # Required for tenant context switching

            connection.set_tenant(tenant) # Switch to the newly created tenant's schema

            try:
                # Check if user already exists in this tenant (should ideally not happen on create)
                if TenantUser.objects.filter(email__iexact=admin_email).exists():
                     # This case shouldn't be hit on tenant creation if email validation is correct
                     # but handle defensively. Maybe log a warning.
                     print(f"Warning: Admin user {admin_email} already exists in schema {tenant.schema_name}.")
                     # Decide how to handle: raise error, skip, or update? Skipping for now.
                     admin_user = TenantUser.objects.get(email__iexact=admin_email)
                else:
                    # Create the tenant user
                    admin_user = TenantUser.objects.create_user(
                        username=admin_email,
                        email=admin_email,
                        password=admin_password,
                        first_name=admin_first_name,
                        last_name=admin_last_name,
                        is_staff=True # Tenant admins might need staff access
                    )

                # Create or update the profile for the admin user
                # Note: Assumes this registration is for a Company Admin initially
                profile, created = UserProfile.objects.update_or_create(
                    user=admin_user,
                    defaults={
                        'nationality':'IN', # Or get from input if available
                        'is_company_admin':True, # This user administers this tenant/company
                        'is_tenant_admin':True,  # Also a tenant admin
                        'is_email_verified':True, # Assume verified for initial admin
                        'otp':None,
                        'totp_secret':None,
                        'is_2fa_enabled':False,
                        'needs_2fa_setup':False,
                        'recovery_codes':None,
                        'updated_at':timezone.now(),
                        'company_id': tenant.id # Link profile to this tenant
                    }
                )
                if created:
                    profile.created_at = timezone.now()
                    profile.save(update_fields=['created_at'])

            except Exception as e:
                print(f"Error creating admin user or profile for tenant {tenant.schema_name}: {str(e)}")
                # Decide on error handling: delete tenant? Log error? Raise?
                # Raising error to prevent incomplete setup
                tenant.delete() # Rollback tenant creation
                raise serializers.ValidationError(f"Failed to create tenant admin: {e}") from e

            finally:
                # Always switch back to the public schema
                connection.set_schema_to_public()

        return tenant

# User Profile Serializer (Read-only display)
class UserProfileSerializer(serializers.ModelSerializer):
    """
    Read-only serializer for the UserProfile model.
    """
    # Assuming 'user' field in UserProfile points to TenantUser model for tenant context
    # If it points to the base User model, you might need UserSerializer here.
    user = serializers.PrimaryKeyRelatedField(read_only=True) # Display user ID

    class Meta:
        model = UserProfile
        fields = ('id', 'user', 'nationality', 'is_company_admin', 'is_tenant_admin',
                  'is_email_verified', 'is_2fa_enabled', 'needs_2fa_setup', 'company_id')
        read_only_fields = ('id', 'user', 'company_id') # Make most fields read-only for display

# --- Other Auth/Utility Serializers ---

class RegistrationSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    password = serializers.CharField(required=True, write_only=True)
    company_name = serializers.CharField(required=True)
    industry = serializers.CharField(required=False, allow_blank=True)
    company_size = serializers.CharField(required=False, allow_blank=True)
    country = serializers.CharField(required=False, allow_blank=True)
    nationality = serializers.CharField(required=False, allow_blank=True)

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

class PasswordResetConfirmSerializer(serializers.Serializer):
    token = serializers.CharField(required=True)
    password = serializers.CharField(required=True, write_only=True, min_length=8)

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(required=True, write_only=True, min_length=8)

class OTPVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    otp = serializers.CharField(required=True, max_length=6, min_length=6)

# --- 2FA Serializers ---

class TwoFactorSetupSerializer(serializers.Serializer):
    pass # Usually just triggers the setup process, might return QR code URL/secret

class TwoFactorSetupConfirmRequestSerializer(serializers.Serializer):
    token = serializers.CharField(required=True, max_length=6, min_length=6) # OTP Token

class TwoFactorSetupConfirmResponseSerializer(serializers.Serializer):
    recovery_codes = serializers.ListField(child=serializers.CharField())

class TwoFactorVerifyRequestSerializer(serializers.Serializer):
    token = serializers.CharField(required=True, max_length=6, min_length=6) # OTP Token

class TwoFactorRecoveryVerifyRequestSerializer(serializers.Serializer):
    recovery_code = serializers.CharField(required=True)

class TwoFactorLoginResponseSerializer(serializers.Serializer):
    # Response after initial login, indicating if 2FA is needed
    requires_2fa = serializers.BooleanField(required=False, default=False)
    needs_2fa_setup = serializers.BooleanField(required=False, default=False)
    user_id = serializers.IntegerField()
    temp_token = serializers.CharField(required=False, allow_null=True) # Temporary token for 2FA step
    message = serializers.CharField(required=False, allow_null=True)
    # Optionally return some initial data if 2FA is not required
    tenant = serializers.JSONField(required=False, allow_null=True)
    token = serializers.CharField(required=False, allow_null=True) # Final auth token
    user = serializers.JSONField(required=False, allow_null=True) # User details


# --- Admin & RBAC Serializers ---

class UserAdminSerializer(serializers.ModelSerializer):
    """
    Serializer for admin management of base users (e.g., in superadmin).
    """
    profile = serializers.SerializerMethodField()

    class Meta:
        model = User # Use base User model
        fields = ('id', 'username', 'email', 'first_name', 'last_name', 'is_active', 'is_staff', 'is_superuser', 'date_joined', 'profile')
        read_only_fields = ('id', 'date_joined')
        # Define writable fields as needed for admin updates

    def get_profile(self, obj):
        # Similar to UserSerializer.get_profile
        try:
            profile = UserProfile.objects.get(user_id=obj.id)
            return {
                'is_company_admin': profile.is_company_admin,
                'is_tenant_admin': profile.is_tenant_admin,
                'nationality': profile.nationality,
                'is_email_verified': profile.is_email_verified,
                'company_id': profile.company_id
            }
        except UserProfile.DoesNotExist:
            return None
        except AttributeError:
             return None

class PermissionSerializer(serializers.ModelSerializer):
    """
    Serializer for the Permission model.
    """
    class Meta:
        model = Permission
        fields = ['id', 'name', 'codename', 'description']
        read_only_fields = ['id']

class RoleSerializer(serializers.ModelSerializer):
    """
    Serializer for the Role model. Includes related permissions.
    """
    permissions = PermissionSerializer(many=True, read_only=True, source='permission_set') # Efficiently get related permissions

    class Meta:
        model = Role
        fields = ['id', 'name', 'description', 'permissions']
        read_only_fields = ['id']
        # Allow writing 'name' and 'description'

# UserRole Serializer (For assigning roles to users)
class UserRoleSerializer(serializers.ModelSerializer):
    """
    Serializer for the UserRole model (the through model).
    Used for associating a User with a Role.
    """
    # Display role details when reading
    role = RoleSerializer(read_only=True)
    # Allow assigning role by ID when writing
    role_id = serializers.PrimaryKeyRelatedField(
        queryset=Role.objects.all(),
        write_only=True,
        source='role' # Map role_id input to the 'role' field of UserRole model
    )
    # Assuming 'user' field is set in the view or context
    user = serializers.PrimaryKeyRelatedField(read_only=True) # Show user ID

    class Meta:
        model = UserRole
        fields = ['id', 'user', 'role', 'role_id']
        read_only_fields = ['id', 'user'] # User is typically set contextually

# Tenant User Display Serializer (Read-only)
class TenantUserDisplaySerializer(serializers.ModelSerializer):
    """
    Serializer for displaying tenant users with profile and roles. Read-only.
    Uses the TenantUser model.
    """
    profile = serializers.SerializerMethodField()
    roles = RoleSerializer(many=True, read_only=True, source='role_set') # Get roles via UserRole reverse relation

    class Meta:
        model = TenantUser # Use the tenant-specific user model
        fields = ('id', 'email', 'username', 'first_name', 'last_name',
                  'is_active', 'is_staff', 'date_joined', 'profile', 'roles')
        read_only_fields = fields # Make all fields read-only for display

    def get_profile(self, obj):
        """ Get the user profile data for the tenant user. """
        try:
            # Assumes UserProfile relates to TenantUser via 'user' field
            profile = UserProfile.objects.get(user=obj)
            return {
                'is_company_admin': profile.is_company_admin,
                'is_tenant_admin': profile.is_tenant_admin,
                'nationality': profile.nationality,
                'is_email_verified': profile.is_email_verified,
                'is_2fa_enabled': profile.is_2fa_enabled,
                'needs_2fa_setup': profile.needs_2fa_setup,
                'company_id': profile.company_id
            }
        except UserProfile.DoesNotExist:
            return None
        except AttributeError:
            return None

# Tenant User Creation Serializer (Write-only)
class TenantUserCreateSerializer(serializers.Serializer):
    """
    Serializer for creating tenant users by a Tenant Admin.
    Handles creation of TenantUser, UserProfile, and assigns an initial Role.
    """
    email = serializers.EmailField(required=True)
    first_name = serializers.CharField(required=True, max_length=150)
    last_name = serializers.CharField(required=True, max_length=150)
    nationality = serializers.CharField(required=False, allow_blank=True, allow_null=True, max_length=100, default='')
    role_id = serializers.PrimaryKeyRelatedField(
        queryset=Role.objects.all(),
        required=True,
        allow_null=False,
        write_only=True,
        help_text="ID of the initial tenant role"
    )
    user_type = serializers.ChoiceField(
        choices=[('internal', 'Internal User'), ('external', 'External User')],
        required=False,
        default='external',
        help_text="Type of user. Internal users have is_staff=True, external users have is_staff=False"
    )
    password = serializers.CharField(
        write_only=True,
        required=False, # Optional: If not provided, random password generated
        allow_null=True,
        allow_blank=True,
        min_length=8,
        style={'input_type': 'password'},
        help_text="Optional password. If not provided, a random 12-character password will be generated."
    )
    password_confirm = serializers.CharField(
        write_only=True,
        required=False, # Required only if password is provided
        allow_null=True,
        allow_blank=True,
        style={'input_type': 'password'},
        help_text="Confirmation of the password. Required if password is provided."
    )
    generate_password = serializers.BooleanField(required=False, default=True)

    def validate_email(self, value):
        """ Validate email uniqueness within the current tenant schema. """
        if not value:
            raise serializers.ValidationError("Email is required.")
        
        email = value.lower()
        if TenantUser.objects.filter(email=email).exists():
            raise serializers.ValidationError("A user with this email already exists in this tenant.")
        return email

    def validate_role_id(self, value):
        """ Validate that the role exists (queryset already does this). """
        # You could add checks here if only specific roles are assignable by certain users
        return value
    
    def validate_first_name(self, value):
        """ Ensure first_name is not empty """
        if not value or not value.strip():
            raise serializers.ValidationError("First name is required.")
        return value.strip()
    
    def validate_last_name(self, value):
        """ Ensure last_name is not empty """
        if not value or not value.strip():
            raise serializers.ValidationError("Last name is required.")
        return value.strip()

    def validate(self, data):
        """ Validate that passwords match if provided. """
        password = data.get('password')
        password_confirm = data.get('password_confirm')

        # If password is provided and not empty
        if password and password.strip():
            # Password confirmation is required
            if not password_confirm or not password_confirm.strip():
                raise serializers.ValidationError({"password_confirm": "Password confirmation is required when setting a password."})
            
            # Passwords must match
            if password != password_confirm:
                raise serializers.ValidationError({"password_confirm": ["Passwords do not match."]})
        
        # Ensure user_type is provided
      #  if 'user_type' not in data or not data['user_type']:
    #     raise serializers.ValidationError({"user_type": "User type is required."})

        return data

    def create(self, validated_data):
        """
        Create TenantUser, UserProfile, and assign Role.
        Expects 'tenant' object in context: serializer.save(tenant=request.tenant)
        """
        # We moved imports like TenantUser, UserRole, UserProfile to the top of the file
        # If keeping them local: from .models import TenantUser, UserRole, UserProfile

        validated_data.pop('password_confirm', None)
        role = validated_data.pop('role_id', None)
        nationality = validated_data.pop('nationality', None) # Get nationality if provided
        generate_password = validated_data.pop('generate_password', True)  # Default to True if not provided

        # --- Determine Password ---
        password_provided = 'password' in validated_data and validated_data['password'] is not None
        if not password_provided and generate_password:
            alphabet = string.ascii_letters + string.digits + string.punctuation.replace('"', '').replace("'", "").replace("`", "") # Avoid problematic chars
            password = ''.join(secrets.choice(alphabet) for _ in range(12))
            generated_password = password
        elif password_provided:
            password = validated_data['password']
            generated_password = None
        else:
            # This case should not happen due to validation, but just in case
            raise serializers.ValidationError({"password": "Password is required when automatic generation is disabled."})

        user = None
        profile = None
        # Consider using a transaction here: from django.db import transaction
        # with transaction.atomic():
        # --- User Creation ---
        try:
            user = TenantUser.objects.create_user(
                email=validated_data['email'],
                password=password,
                first_name=validated_data['first_name'],
                last_name=validated_data['last_name'],
                username=validated_data['email'] # Use email as username
            )
            user.user_type = validated_data['user_type']
            if validated_data['user_type'] == 'internal':
                user.is_staff = True
            else:
                user.is_staff = False
            user.save()
        except Exception as e:
             raise serializers.ValidationError({"detail": f"Failed to create user: {e}"}) from e

        # --- Profile Creation ---
        try:
            # --- IMPORTANT: Get tenant from context passed by the view ---
            current_tenant = self.context.get('tenant', None)
            if not current_tenant:
                 # Clean up created user if tenant context is missing
                 if user: user.delete()
                 raise serializers.ValidationError({"detail": "Tenant context is missing. Cannot create user profile."})
            company_id = current_tenant.id

            profile = UserProfile.objects.create(
                user=user,
                nationality=nationality, # Use provided or None
                is_company_admin=False,  # Default for tenant-created users
                is_tenant_admin=False,   # Default; role assignment implies permissions
                is_email_verified=False, # Requires verification workflow
                created_at=timezone.now(),
                updated_at=timezone.now(),
                company_id=company_id # Link profile to the current tenant
                # Add other UserProfile fields with defaults if necessary
            )
        except Exception as e:
             # Clean up created user if profile creation fails
             if user: user.delete()
             raise serializers.ValidationError({"detail": f"Failed to create user profile: {e}"}) from e

        # --- Role Assignment ---
        try:
            if role:
                UserRole.objects.create(user=user, role=role)
        except Exception as e:
            # Clean up profile and user if role assignment fails
            if profile: profile.delete()
            if user: user.delete()
            raise serializers.ValidationError({"detail": f"Failed to assign role to user: {e}"}) from e

        # --- Prepare Result ---
        # Return serialized data of the created user and assigned role
        result = {
            # Use the display serializer to format the output user object
            'user': TenantUserDisplaySerializer(user, context=self.context).data,
            'role': RoleSerializer(role).data if role else None # Include details of the assigned role
        }

        if generated_password:
            result['generated_password'] = generated_password
            # Consider how to securely communicate this password (e.g., email, display once)

        # The serializer's save() method returns the result of create()
        return result