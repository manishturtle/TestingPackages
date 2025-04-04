from django.apps import AppConfig


class EcommTenantAdminsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'ecomm_tenant.ecomm_tenant_admins'
    
    def ready(self):
        import ecomm_tenant.ecomm_tenant_admins.signals
