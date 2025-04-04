from django.contrib import admin
from .models import Tenant, SubscriptionPlan, User, Domain, CrmClient
from ecomm_tenant.ecomm_tenant_admins.models import UserProfile

# Register your models here.
@admin.register(Tenant)
class TenantAdmin(admin.ModelAdmin):
    list_display = ('name', 'schema_name', 'status', 'environment', 'tenant_admin_email', 'client', 'created_at')
    search_fields = ('name', 'schema_name', 'tenant_admin_email')
    list_filter = ('status', 'environment', 'created_at')
    autocomplete_fields = ['client']

@admin.register(SubscriptionPlan)
class SubscriptionPlanAdmin(admin.ModelAdmin):
    list_display = ('name', 'price', 'is_active')
    search_fields = ('name',)
    list_filter = ('is_active', 'created_at')

@admin.register(Domain)
class DomainAdmin(admin.ModelAdmin):
    list_display = ('domain', 'folder', 'tenant')
    search_fields = ('domain', 'folder')
    list_filter = ('tenant',)

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'company_id', 'is_company_admin', 'created_at')
    list_filter = ('is_company_admin', 'created_at')
    search_fields = ('user__email', 'user__username')

@admin.register(CrmClient)
class CrmClientAdmin(admin.ModelAdmin):
    list_display = ('client_name', 'contact_person_email', 'created_at', 'tenant_count')
    search_fields = ('client_name', 'contact_person_email')
    list_filter = ('created_at',)
    
    def tenant_count(self, obj):
        return obj.tenants.count()
    tenant_count.short_description = 'Number of Tenants'
