import os
import shutil
import django
from django.conf import settings

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ecomm_product.settings')
django.setup()

# Apps to reset migrations for
apps = ['accounts', 'ecomm_tenant.ecomm_tenant_admins']

for app in apps:
    migrations_dir = os.path.join(app, 'migrations')
    
    # Keep __init__.py file
    init_file = os.path.join(migrations_dir, '__init__.py')
    has_init = os.path.exists(init_file)
    
    # Remove all migration files
    if os.path.exists(migrations_dir):
        for filename in os.listdir(migrations_dir):
            if filename != '__init__.py' and filename.endswith('.py'):
                file_path = os.path.join(migrations_dir, filename)
                if os.path.isfile(file_path):
                    os.remove(file_path)
                    print(f"Removed {file_path}")
    else:
        os.makedirs(migrations_dir)
        print(f"Created migrations directory for {app}")
    
    # Create __init__.py if it doesn't exist
    if not has_init:
        with open(init_file, 'w') as f:
            pass
        print(f"Created {init_file}")

print("Migration files have been reset. Now run 'python manage.py makemigrations accounts ecomm_tenant.ecomm_tenant_admins' to create new migrations.")
