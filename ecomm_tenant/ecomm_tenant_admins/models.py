from django.db import models
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.contrib.auth.models import Group, Permission
from django.utils.translation import gettext_lazy as _

# Create your models here.

class TenantUserManager(BaseUserManager):
    """
    Custom manager for TenantUser that uses email as the unique identifier
    instead of username for authentication.
    """
    def create_user(self, email, password=None, **extra_fields):
        """
        Create and save a user with the given email and password.
        """
        if not email:
            raise ValueError(_('The Email field must be set'))
        
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """
        Create and save a superuser with the given email and password.
        In tenant context, a superuser is a tenant admin.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))
        
        return self.create_user(email, password, **extra_fields)

class TenantUser(AbstractBaseUser, PermissionsMixin):
    """
    Custom User model for tenant schemas.
    Uses email as the unique identifier instead of username for authentication.
    
    This model is specific to tenant schemas and should not be used in the public schema.
    """
    email = models.EmailField(_('email address'), unique=True)
    username = models.CharField(_('username'), max_length=150, blank=True)
    first_name = models.CharField(_('first name'), max_length=150, blank=True)
    last_name = models.CharField(_('last name'), max_length=150, blank=True)
    is_active = models.BooleanField(
        _('active'),
        default=True,
        help_text=_(
            'Designates whether this user should be treated as active. '
            'Unselect this instead of deleting accounts.'
        ),
    )
    is_staff = models.BooleanField(
        _('staff status'),
        default=False,
        help_text=_('Designates whether the user can log into the tenant admin site.'),
    )
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)
    
    # Add related_name attributes to avoid clashes with the User model in public schema
    groups = models.ManyToManyField(
        Group,
        verbose_name=_('groups'),
        blank=True,
        help_text=_(
            'The groups this user belongs to. A user will get all permissions '
            'granted to each of their groups.'
        ),
        related_name='tenant_user_set',
        related_query_name='tenant_user',
    )
    user_permissions = models.ManyToManyField(
        Permission,
        verbose_name=_('user permissions'),
        blank=True,
        help_text=_('Specific permissions for this user.'),
        related_name='tenant_user_set',
        related_query_name='tenant_user',
    )
    
    objects = TenantUserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []  # Email is already required by default
    
    class Meta:
        verbose_name = _('tenant user')
        verbose_name_plural = _('tenant users')
        ordering = ['email']
    
    def __str__(self):
        return self.email
    
    def get_full_name(self):
        """
        Return the first_name plus the last_name, with a space in between.
        """
        full_name = f"{self.first_name} {self.last_name}"
        return full_name.strip()
    
    def get_short_name(self):
        """Return the short name for the user."""
        return self.first_name

class UserProfile(models.Model):
    """
    Model to extend the built-in User model with additional fields.
    """
    user = models.OneToOneField(TenantUser, on_delete=models.CASCADE, related_name='profile')
    # Changed from ForeignKey to IntegerField to remove dependency on ecomm_superadmin.Company
    company_id = models.IntegerField(null=True, blank=True)
    nationality = models.CharField(max_length=100, null=True, blank=True)
    is_company_admin = models.BooleanField(default=False)
    is_tenant_admin = models.BooleanField(default=False)  # Added field to identify tenant administrators
    is_email_verified = models.BooleanField(default=False)
    otp = models.CharField(max_length=6, null=True, blank=True)
    # 2FA fields
    totp_secret = models.CharField(max_length=255, null=True, blank=True)
    is_2fa_enabled = models.BooleanField(default=False)
    needs_2fa_setup = models.BooleanField(default=False)  # Added field to track if user needs to set up 2FA
    recovery_codes = models.JSONField(null=True, blank=True)  # Store recovery codes as JSON
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        if self.nationality:
            return f"{self.user.email} - {self.nationality}"
        return f"{self.user.email}"

class Role(models.Model):
    """
    Model to define roles in the system.
    """
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name

class Permission(models.Model):
    """
    Model to define permissions in the system.
    """
    name = models.CharField(max_length=100, unique=True)
    codename = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name

class RolePermission(models.Model):
    """
    Model to define which permissions are assigned to which roles.
    """
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='permissions')
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE, related_name='roles')
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ('role', 'permission')
    
    def __str__(self):
        return f"{self.role.name} - {self.permission.name}"

class UserRole(models.Model):
    """
    Model to assign roles to users.
    """
    user = models.ForeignKey(TenantUser, on_delete=models.CASCADE, related_name='user_roles')
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='user_roles')
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ('user', 'role')
    
    def __str__(self):
        return f"{self.user.username} - {self.role.name}"

class PendingRegistration(models.Model):
    """
    Model to store pending user registrations before OTP verification.
    """
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150)
    nationality = models.CharField(max_length=100, null=True, blank=True)
    company_name = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.email

class OTP(models.Model):
    """
    Model to store One-Time Passwords (OTPs) for password reset functionality.
    This model provides better persistence and auditability compared to cache-based solutions.
    """
    user = models.ForeignKey(
        TenantUser, 
        on_delete=models.CASCADE,
        related_name='password_reset_otps'
    )
    otp_code = models.CharField(
        max_length=6, 
        db_index=True
    )
    created_at = models.DateTimeField(
        auto_now_add=True
    )
    expires_at = models.DateTimeField()
    
    class Meta:
        verbose_name = "One-Time Password"
        verbose_name_plural = "One-Time Passwords"
    
    def __str__(self):
        return f"OTP for {self.user.email}"
    
    def is_valid(self):
        """
        Check if the OTP is still valid (not expired).
        """
        return timezone.now() <= self.expires_at
    
    @classmethod
    def generate_otp(cls, user, expiry_minutes=10):
        """
        Generate a new OTP for the given user.
        Deletes any existing OTPs for the user first.
        """
        # Delete any existing OTPs for this user
        cls.objects.filter(user=user).delete()
        
        # Generate a random 6-digit OTP
        import random
        otp_code = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        
        # Set expiry time
        expires_at = timezone.now() + timedelta(minutes=expiry_minutes)
        
        # Create and save the OTP
        otp = cls(
            user=user,
            otp_code=otp_code,
            expires_at=expires_at
        )
        otp.save()
        
        return otp_code

class Company(models.Model):
    """
    Model to represent a company in the tenant schema.
    Each company can have multiple users within the tenant.
    """
    name = models.CharField(max_length=255)
    country = models.CharField(max_length=100, blank=True, null=True)
    client = models.ForeignKey(
        'TenantCrmClient',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='companies',
        db_column='client_id',  # Keep the same column name in the database
        help_text='The CRM client associated with this company'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name
    
    class Meta:
        verbose_name = "Company"
        verbose_name_plural = "Companies"
        db_table = "ecomm_tenant_admins_company"

class TenantCrmClient(models.Model):
    """
    Tenant-specific CRM Client model for storing client information within a tenant schema.
    This model has a manually set primary key (client_id) that is not auto-created.
    """
    client_id = models.IntegerField(primary_key=True)
    client_name = models.CharField(max_length=255)
    contact_person_email = models.EmailField(max_length=255)
    created_by = models.EmailField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_by = models.EmailField(max_length=255)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.client_name
    
    class Meta:
        verbose_name = "Tenant CRM Client"
        verbose_name_plural = "Tenant CRM Clients"
        db_table = 'ecomm_tenant_admins_crmclients'
