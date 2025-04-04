from django.db import models
from django.core.validators import RegexValidator
from django_tenants.models import TenantMixin, DomainMixin
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from datetime import datetime, timedelta

# Create your models here.

class SubscriptionPlan(models.Model):
    """
    Model to represent subscription plans available for tenants.
    """
    name = models.CharField(max_length=100, help_text="Name of the subscription plan")
    description = models.TextField(blank=True, help_text="Detailed description of the plan features")
    price = models.DecimalField(max_digits=10, decimal_places=2, help_text="Monthly price of the plan")
    max_users = models.PositiveIntegerField(default=5, help_text="Maximum number of users allowed")
    max_storage = models.PositiveIntegerField(default=5, help_text="Maximum storage in GB")
    features = models.JSONField(blank=True, null=True, help_text="JSON field containing plan features")
    is_active = models.BooleanField(default=True, help_text="Whether this plan is currently available")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.name} (${self.price}/month)"
    
    class Meta:
        verbose_name = "Subscription Plan"
        verbose_name_plural = "Subscription Plans"

class TenantManager(models.Manager):
    """Custom manager for the Tenant model to provide additional functionality."""
    def create_tenant(self, name, schema_name, **kwargs):
        """Create a new tenant with the given name and schema_name."""
        tenant = self.model(
            name=name,
            schema_name=schema_name,
            **kwargs
        )
        tenant.save()
        return tenant

class Tenant(TenantMixin):
    """
    Model representing a tenant in the multi-tenant SaaS ERP system.
    Inherits from TenantMixin provided by django-tenants.
    """
    auto_create_schema = True  # Ensure schemas are automatically created
    name = models.CharField(max_length=255, help_text="Name of the tenant/client")
    url_suffix = models.CharField(
        max_length=63,
        unique=True,
        blank=True,
        null=True,
        validators=[
            RegexValidator(
                regex=r'^[a-zA-Z0-9-]+$',
                message='URL suffix can only contain letters, numbers, and hyphens.',
                code='invalid_url_suffix'
            ),
        ],
        help_text='Custom URL suffix for this tenant (e.g., "company-name" for company-name.example.com). '
                 'Only letters, numbers, and hyphens are allowed.'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    STATUS_CHOICES = (
        ('active', 'Active'),
        ('trial', 'Trial'),
        ('suspended', 'Suspended'),
        ('inactive', 'Inactive'),
    )
    status = models.CharField(
        max_length=20, 
        choices=STATUS_CHOICES, 
        default='trial',
        help_text="Current status of the tenant"
    )
    
    ENVIRONMENT_CHOICES = (
        ('development', 'Development'),
        ('testing', 'Testing'),
        ('staging', 'Staging'),
        ('production', 'Production'),
    )
    environment = models.CharField(
        max_length=20, 
        choices=ENVIRONMENT_CHOICES, 
        default='production',
        help_text="Environment where this tenant is deployed"
    )
    
    trial_end_date = models.DateField(
        null=True, 
        blank=True, 
        help_text='Date when the trial period ends'
    )
    
    paid_until = models.DateField(
        null=True, 
        blank=True, 
        help_text='Date until which the subscription is paid'
    )
    
    subscription_plan = models.ForeignKey(
        'SubscriptionPlan',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='tenants',
        help_text='The subscription plan this tenant is on'
    )
    
    client = models.ForeignKey(
        'CrmClient',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='tenants',
        help_text='The CRM client associated with this tenant'
    )
    
    # Field name in the model should match the database column name
    tenant_admin_email = models.EmailField(
        max_length=255,
        null=True,
        blank=True,
        help_text='Email address of the tenant admin'
    )
    
    def __str__(self):
        return self.name
    
    objects = TenantManager()
    
    def save(self, *args, **kwargs):
        # If schema_name is not set, use the url_suffix as schema_name
        if not self.schema_name and self.url_suffix:
            self.schema_name = self.url_suffix
        
        # Call the parent save method
        super().save(*args, **kwargs)
    
    class Meta:
        db_table = 'ecomm_superadmin_tenants'
        verbose_name = 'Tenant'
        verbose_name_plural = 'Tenants'

class User(AbstractUser):
    """
    Custom User model for the application.
    Extends Django's AbstractUser to add additional fields and functionality.
    """
    email = models.EmailField(unique=True)
    
    # Use email as the username field
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    
    def __str__(self):
        return self.email
    
    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"

class CrmClient(models.Model):
    """
    CRM Client model for storing client information.
    """
    client_name = models.CharField(max_length=255)
    contact_person_email = models.EmailField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.client_name
    
    class Meta:
        db_table = 'ecomm_superadmin_crmclients'
        verbose_name = "CRM Client"
        verbose_name_plural = "CRM Clients"

class Domain(DomainMixin):
    """
    Domain model for django_tenants compatibility.
    Maps domains to tenants for routing.
    """
    tenant = models.ForeignKey(
        Tenant, 
        on_delete=models.CASCADE, 
        related_name='domains'
    )
    folder = models.CharField(max_length=100, null=True, blank=True, 
                             help_text="Subfolder name for this tenant (e.g., 'qa' for localhost/qa/)")
    
    def __str__(self):
        if self.folder:
            return f"{self.domain}/{self.folder}"
        return self.domain
    
    class Meta:
        verbose_name = "Domain"
        verbose_name_plural = "Domains"
        unique_together = ('domain', 'folder')
