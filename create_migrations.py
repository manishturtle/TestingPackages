import os
import sys
import django
from django.db.migrations.writer import MigrationWriter
from django.db.migrations import Migration, CreateModel, AddField
from django.db import models
import django.db.models.deletion

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'erp_project.settings')
django.setup()

# Create migrations directory if it doesn't exist
os.makedirs('accounts/migrations', exist_ok=True)
os.makedirs('ecomm_tenant/ecomm_tenant_admins/migrations', exist_ok=True)

# Create __init__.py if it doesn't exist
if not os.path.exists('accounts/migrations/__init__.py'):
    with open('accounts/migrations/__init__.py', 'w') as f:
        pass

if not os.path.exists('ecomm_tenant/ecomm_tenant_admins/migrations/__init__.py'):
    with open('ecomm_tenant/ecomm_tenant_admins/migrations/__init__.py', 'w') as f:
        pass

# Create migration for accounts app
accounts_operations = [
    CreateModel(
        name='User',
        fields=[
            ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
            ('password', models.CharField(max_length=128, verbose_name='password')),
            ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
            ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
            ('username', models.CharField(max_length=150, unique=True)),
            ('email', models.EmailField(max_length=254, unique=True)),
            ('first_name', models.CharField(blank=True, max_length=150)),
            ('last_name', models.CharField(blank=True, max_length=150)),
            ('is_staff', models.BooleanField(default=False)),
            ('is_active', models.BooleanField(default=True)),
            ('date_joined', models.DateTimeField(auto_now_add=True)),
        ],
        options={
            'verbose_name': 'User',
            'verbose_name_plural': 'Users',
        },
    ),
    CreateModel(
        name='SubscriptionPlan',
        fields=[
            ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
            ('name', models.CharField(help_text='Name of the subscription plan', max_length=100)),
            ('description', models.TextField(blank=True, help_text='Detailed description of the plan features')),
            ('price', models.DecimalField(decimal_places=2, help_text='Monthly price of the plan', max_digits=10)),
            ('max_users', models.PositiveIntegerField(default=5, help_text='Maximum number of users allowed')),
            ('max_storage', models.PositiveIntegerField(default=5, help_text='Maximum storage in GB')),
            ('features', models.JSONField(blank=True, help_text='JSON field containing plan features', null=True)),
            ('is_active', models.BooleanField(default=True, help_text='Whether this plan is currently available')),
            ('created_at', models.DateTimeField(auto_now_add=True)),
            ('updated_at', models.DateTimeField(auto_now=True)),
        ],
        options={
            'verbose_name': 'Subscription Plan',
            'verbose_name_plural': 'Subscription Plans',
        },
    ),
    CreateModel(
        name='Client',
        fields=[
            ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
            ('schema_name', models.CharField(max_length=63, unique=True)),
            ('name', models.CharField(help_text='Name of the tenant/client', max_length=255)),
            ('description', models.TextField(blank=True, help_text='Description of the tenant/client', null=True)),
            ('created_at', models.DateTimeField(auto_now_add=True)),
            ('updated_at', models.DateTimeField(auto_now=True)),
            ('status', models.CharField(choices=[('active', 'Active'), ('trial', 'Trial'), ('suspended', 'Suspended'), ('inactive', 'Inactive')], default='trial', help_text='Current status of the tenant', max_length=20)),
            ('subscription_plan', models.ForeignKey(blank=True, help_text='The subscription plan this client is on', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='clients', to='superadmin.subscriptionplan')),
        ],
        options={
            'verbose_name': 'Client',
            'verbose_name_plural': 'Clients',
        },
    ),
    CreateModel(
        name='Domain',
        fields=[
            ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
            ('domain', models.CharField(max_length=253, unique=True)),
            ('is_primary', models.BooleanField(default=True)),
            ('tenant', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='domains', to='superadmin.client')),
        ],
        options={
            'verbose_name': 'Domain',
            'verbose_name_plural': 'Domains',
        },
    ),
    CreateModel(
        name='Company',
        fields=[
            ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
        ],
        options={
            'verbose_name': 'Company',
            'verbose_name_plural': 'Companies',
        },
    ),
]

accounts_migration = Migration('0001_initial', 'accounts')
accounts_migration.dependencies = [('auth', '0012_alter_user_first_name_max_length')]
accounts_migration.operations = accounts_operations

# Create migration for ecomm_tenant.ecomm_tenant_admins app
tenant_admins_operations = [
    CreateModel(
        name='UserProfile',
        fields=[
            ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
            ('nationality', models.CharField(max_length=100, null=True)),
            ('is_company_admin', models.BooleanField(default=False)),
            ('is_tenant_admin', models.BooleanField(default=False)),
            ('is_email_verified', models.BooleanField(default=False)),
            ('otp', models.CharField(max_length=6, null=True)),
            ('totp_secret', models.CharField(max_length=255, null=True)),
            ('is_2fa_enabled', models.BooleanField(default=False)),
            ('needs_2fa_setup', models.BooleanField(default=False)),
            ('recovery_codes', models.JSONField(null=True)),
            ('created_at', models.DateTimeField(auto_now_add=True)),
            ('updated_at', models.DateTimeField(auto_now=True)),
            ('company', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='superadmin.company')),
            ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='profile', to='superadmin.user')),
        ],
    ),
]

tenant_admins_migration = Migration('0001_initial', 'ecomm_tenant.ecomm_tenant_admins')
tenant_admins_migration.dependencies = [('accounts', '0001_initial')]
tenant_admins_migration.operations = tenant_admins_operations

# Write the migration files
accounts_writer = MigrationWriter(accounts_migration)
with open('accounts/migrations/0001_initial.py', 'w') as f:
    f.write(accounts_writer.as_string())

tenant_admins_writer = MigrationWriter(tenant_admins_migration)
with open('ecomm_tenant/ecomm_tenant_admins/migrations/0001_initial.py', 'w') as f:
    f.write(tenant_admins_writer.as_string())

print("Migration files created successfully!")
print("Now run 'python manage.py migrate' to apply the migrations.")
