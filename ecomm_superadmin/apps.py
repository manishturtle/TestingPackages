from django.apps import AppConfig


class EcommSuperadminConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'ecomm_superadmin'
    
    def ready(self):
        """
        Import signal handlers when the app is ready
        """
        import ecomm_superadmin.signals
