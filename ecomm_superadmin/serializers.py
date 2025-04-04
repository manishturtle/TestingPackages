# ecomm_superadmin/serializers.py

from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Tenant, Domain, SubscriptionPlan, CrmClient # Import SHARED models from this app
# Import TENANT models from their correct location
from ecomm_tenant.ecomm_tenant_admins.models import UserProfile, Role, UserRole

User = get_user_model() # Get the active User model (ecomm_superadmin.User)

# --- Helper Serializers (Potentially used by UserSerializer) ---

class RoleSerializer(serializers.ModelSerializer):
    """ Serializer for the tenant-specific Role model (read-only context here) """
    class Meta:
        model = Role
        fields = ['name'] # Only show name for context

class UserRoleSerializer(serializers.ModelSerializer):
    """ Serializer for the tenant-specific UserRole model (read-only context here) """
    role = RoleSerializer(read_only=True)
    class Meta:
        model = UserRole
        fields = ['role']

class UserProfileSimpleSerializer(serializers.ModelSerializer):
    """ A simpler serializer for UserProfile when nested """
    class Meta:
        model = UserProfile
        # List only the fields you want to expose when profile is nested in User
        fields = ['is_company_admin', 'is_tenant_admin', 'is_email_verified', 'is_2fa_enabled', 'needs_2fa_setup']

# --- Main Serializers for ecomm_superadmin ---

class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for the SHARED User model. Safely includes profile and roles.
    """
    profile = serializers.SerializerMethodField()
    roles = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'is_active', 'is_staff', 'is_superuser', 'date_joined',
            #'is_tenant_admin', # Assuming this field is on your custom User model
            'profile', 'roles'
        ]
        read_only_fields = ('id', 'date_joined', 'is_staff', 'is_superuser', 'is_active')
        #, 'is_tenant_admin')

    def get_profile(self, obj):
        """
        Safely attempts to retrieve the UserProfile from the current schema.
        Returns profile data if found (for tenant users in tenant schema),
        None otherwise (e.g., for platform admins in public schema).
        """
        # This works because UserProfile.objects queries the schema
        # set by the django_tenants middleware for the current request.
        try:
            # For platform admins in public schema, return minimal profile data
            if obj.is_staff and not hasattr(obj, 'userprofile'):
                return {
                    'is_company_admin': False,
                    'is_tenant_admin': False,
                    'is_email_verified': True,
                    'is_2fa_enabled': False,
                    'needs_2fa_setup': False
                }
            
            profile = UserProfile.objects.get(user=obj)
            return UserProfileSimpleSerializer(profile).data
        except (UserProfile.DoesNotExist, Exception) as e:
            # Return default profile for platform admins
            if obj.is_staff:
                return {
                    'is_company_admin': False,
                    'is_tenant_admin': False,
                    'is_email_verified': True,
                    'is_2fa_enabled': False,
                    'needs_2fa_setup': False
                }
            return None # Expected for users without a profile in the current schema

    def get_roles(self, obj):
        """
        Safely attempts to retrieve UserRoles from the current schema.
        """
        try:
            # For platform admins in public schema, return admin role
            if obj.is_staff and not UserRole.objects.filter(user=obj).exists():
                return [{'role': {'name': 'Platform Admin'}}]
                
            user_roles = UserRole.objects.filter(user=obj)
            return UserRoleSerializer(user_roles, many=True).data
        except Exception as e:
            # For platform admins, return admin role
            if obj.is_staff:
                return [{'role': {'name': 'Platform Admin'}}]
            return []

class UserAdminSerializer(UserSerializer):
    """
    Serializer specifically for platform admins managing Users.
    Might show more or fewer fields than the standard UserSerializer.
    Inherits profile/roles methods from UserSerializer.
    """
    class Meta(UserSerializer.Meta): # Inherit Meta from UserSerializer
        # Example: Add fields only admins should see/edit, or adjust read_only
        fields = UserSerializer.Meta.fields + ['phone_number'] # Example adding phone
        read_only_fields = ('id', 'date_joined', 'last_login') # Example adjusting read_only

class SubscriptionPlanSerializer(serializers.ModelSerializer):
    """
    Serializer for the SHARED SubscriptionPlan model.
    """
    class Meta:
        model = SubscriptionPlan
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at')

class CrmClientSerializer(serializers.ModelSerializer):
    """Serializer for the CrmClient model."""
    tenant_count = serializers.SerializerMethodField()
    
    class Meta:
        model = CrmClient
        fields = ('id', 'client_name', 'contact_person_email', 'created_at', 'updated_at', 'tenant_count')
        read_only_fields = ('id', 'created_at', 'updated_at', 'tenant_count')
    
    def get_tenant_count(self, obj):
        """Return the number of tenants associated with this client."""
        return obj.tenants.count()

class TenantSerializer(serializers.ModelSerializer):
    """
    Serializer for the SHARED Tenant model (tenants).
    Handles displaying the plan and receiving plan ID for writes.
    Includes write-only fields for creating the initial tenant admin.
    """
    subscription_plan = SubscriptionPlanSerializer(read_only=True) # Nested read
    subscription_plan_id = serializers.PrimaryKeyRelatedField(
        queryset=SubscriptionPlan.objects.all(), # Make sure SubscriptionPlan exists!
        source='subscription_plan',
        write_only=True,
        required=False, # Allow creating tenants without initially assigning a plan
        allow_null=True
    )

    client = CrmClientSerializer(read_only=True)
    client_id = serializers.PrimaryKeyRelatedField(
        queryset=CrmClient.objects.all(),
        source='client',
        write_only=True,
        required=False,  # Changed back to False (optional)
        allow_null=True   # Changed back to True (allow null)
    )

    # Fields for initial tenant admin user creation (write-only)
    admin_email = serializers.EmailField(write_only=True, required=True) # Required for creation
    admin_first_name = serializers.CharField(max_length=150, write_only=True, required=True)
    admin_last_name = serializers.CharField(max_length=150, write_only=True, required=True)
    admin_password = serializers.CharField(max_length=128, write_only=True, required=False, allow_null=True, help_text="Leave blank to auto-generate.")

    class Meta:
        model = Tenant
        fields = [
            'id', 'name', 'schema_name', 'url_suffix', 'created_at', 'updated_at',
            'status', 'environment', 'trial_end_date', 'paid_until',
            'subscription_plan', 'subscription_plan_id', # subscription_plan_id for writing
            'client', 'client_id', # client_id for writing
            'tenant_admin_email', # Include the tenant_admin_email field
            # Include write-only admin fields needed ONLY for creation via this serializer
            'admin_email', 'admin_first_name', 'admin_last_name', 'admin_password'
        ]
        read_only_fields = ('id', 'schema_name', 'created_at', 'updated_at')

    def validate_url_suffix(self, value):
        # Add validation logic for url_suffix if needed (e.g., allowed characters)
        return value

    # Override create method to handle admin fields and logo
    def create(self, validated_data):
        # Extract admin fields
        admin_email = validated_data.pop('admin_email', None)
        admin_first_name = validated_data.pop('admin_first_name', None)
        admin_last_name = validated_data.pop('admin_last_name', None)
        admin_password = validated_data.pop('admin_password', None)
        
        # Get the CRM client if selected
        client = validated_data.get('client', None)
        
        # Create the tenant
        tenant = Tenant.objects.create(**validated_data)
        
        # Create initial admin user for the tenant
        try:
            # Import here to avoid circular imports
            from django.contrib.auth.models import Group
            
            # Generate a random password if not provided
            if not admin_password:
                import secrets
                import string
                alphabet = string.ascii_letters + string.digits
                admin_password = ''.join(secrets.choice(alphabet) for i in range(12))
            
            # Connect to tenant schema
            from django_tenants.utils import tenant_context
            with tenant_context(tenant):
                # Import the TenantUser model from the tenant app
                from ecomm_tenant.ecomm_tenant_admins.models import TenantUser
                
                # Create the user in the tenant schema using TenantUser model
                admin_user = TenantUser.objects.create_user(
                    email=admin_email,
                    username=admin_email,
                    password=admin_password,
                    first_name=admin_first_name,
                    last_name=admin_last_name,
                    is_staff=True,
                    is_superuser=True
                )
                
                # Create UserProfile for the admin user
                from ecomm_tenant.ecomm_tenant_admins.models import UserProfile
                UserProfile.objects.create(
                    user=admin_user,
                    is_tenant_admin=True,
                    is_email_verified=True,
                    is_company_admin=True
                )
                
                # Try to add user to admin group if it exists
                try:
                    admin_group = Group.objects.get(name='Admin')
                    admin_user.groups.add(admin_group)
                except Group.DoesNotExist:
                    # Create admin group if it doesn't exist
                    admin_group = Group.objects.create(name='Admin')
                    admin_user.groups.add(admin_group)
                
                # Save the tenant admin email for reference
                tenant.tenant_admin_email = admin_email
                tenant.save(update_fields=['tenant_admin_email'])
                
                # Create predefined roles for the tenant
                from ecomm_tenant.ecomm_tenant_admins.models import Role
                
                # Define predefined roles
                predefined_roles = [
                    {"name": "Admin", "description": "Full access to all features"},
                    {"name": "Manager", "description": "Can manage most resources but with some restrictions"},
                    {"name": "Editor", "description": "Can edit content but cannot manage users or settings"},
                    {"name": "Viewer", "description": "Read-only access to resources"}
                ]
                
                # Create each predefined role
                for role_data in predefined_roles:
                    Role.objects.create(**role_data)
                
                # Set trial_end_date to 1 month from now if it's not set and status is trial
                if not tenant.trial_end_date and tenant.status == 'trial':
                    from datetime import datetime, timedelta
                    tenant.trial_end_date = datetime.now().date() + timedelta(days=30)
                    tenant.save(update_fields=['trial_end_date'])
                
                # If a CRM client is selected, create a TenantCrmClient entry
                if client:
                    try:
                        # Import the TenantCrmClient model
                        from ecomm_tenant.ecomm_tenant_admins.models import TenantCrmClient
                        import traceback
                        
                        # Use the default creator/updater email
                        created_by_email = "ankit@turtlesoftware.co"
                        
                        # Try to create TenantCrmClient entry with the client data using ORM
                        try:
                            # Set the schema to the tenant's schema
                            from django.db import connection
                            connection.set_schema(tenant.schema_name)
                            
                            # Create a TenantCrmClient entry with the client data
                            TenantCrmClient.objects.create(
                                client_id=client.id,
                                client_name=client.client_name,
                                contact_person_email=client.contact_person_email,
                                created_by=created_by_email,
                                updated_by=created_by_email
                            )
                            print(f"Created TenantCrmClient entry for {client.client_name} in schema {tenant.schema_name}")
                            
                            # Reset schema to public
                            connection.set_schema_to_public()
                        except Exception as orm_e:
                            print(f"Error creating TenantCrmClient via ORM: {str(orm_e)}")
                            traceback.print_exc()
                            
                            # Fallback to direct SQL if ORM approach fails
                            try:
                                cursor = connection.cursor()
                                
                                # Insert the CRM client directly with SQL
                                cursor.execute(f"""
                                INSERT INTO "{tenant.schema_name}".ecomm_tenant_admins_crmclients
                                (client_id, client_name, contact_person_email, created_by, updated_by, created_at, updated_at)
                                VALUES (%s, %s, %s, %s, %s, NOW(), NOW())
                                ON CONFLICT (client_id) DO NOTHING
                                """, [
                                    client.id,
                                    client.client_name,
                                    client.contact_person_email,
                                    created_by_email,
                                    created_by_email
                                ])
                                print(f"Created TenantCrmClient entry via SQL for {client.client_name} in schema {tenant.schema_name}")
                            except Exception as sql_e:
                                print(f"Error creating TenantCrmClient via SQL: {str(sql_e)}")
                                traceback.print_exc()
                    except Exception as e:
                        print(f"Error creating TenantCrmClient: {str(e)}")
                        traceback.print_exc()
        
        except Exception as e:
            # Log the error but don't fail tenant creation
            print(f"Error creating admin user: {str(e)}")
        
        return tenant

class DomainSerializer(serializers.ModelSerializer):
    """
    Serializer for the SHARED Domain model.
    """
    class Meta:
        model = Domain
        fields = '__all__'
        # Consider making 'tenant' read-only or write-only depending on use case
        # read_only_fields = ('tenant',)

class LoginSerializer(serializers.Serializer):
    """
    Serializer for standard login requests (email/password).
    Used by both platform admin and potentially tenant login views.
    """
    email = serializers.EmailField(required=True)
    password = serializers.CharField(
        style={'input_type': 'password'},
        trim_whitespace=False,
        required=True
    )
    # No validate method needed here - authentication happens in the view

# --- Add other serializers needed by ecomm_superadmin views ---
# e.g., PasswordResetRequestSerializer, ChangePasswordSerializer (if handled globally)