from django.contrib import admin
from .models import Company

# Register only the Company model
@admin.register(Company)
class CompanyAdmin(admin.ModelAdmin):
    list_display = ('name', 'country', 'client_id', 'created_at')
    search_fields = ('name', 'country', 'client_id')
    list_filter = ('country',)
