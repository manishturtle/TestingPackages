from django.core.management.base import BaseCommand
from django.db import connection

class Command(BaseCommand):
    help = 'Marks specific migrations as applied without running them'

    def handle(self, *args, **options):
        # List of migrations to mark as applied
        migrations_to_fake = [
            ('authtoken', '0004_alter_tokenproxy_options'),
            ('ecomm_superadmin', '0003_add_tenant_admin_id_remove_company'),
            ('ecomm_tenant_admins', '0002_add_company_model'),
        ]

        with connection.cursor() as cursor:
            for app, migration in migrations_to_fake:
                # Check if the migration is already applied
                cursor.execute(
                    "SELECT EXISTS(SELECT 1 FROM django_migrations WHERE app = %s AND name = %s)",
                    [app, migration]
                )
                already_applied = cursor.fetchone()[0]
                
                if not already_applied:
                    # Insert the migration record
                    cursor.execute(
                        "INSERT INTO django_migrations (app, name, applied) VALUES (%s, %s, NOW())",
                        [app, migration]
                    )
                    self.stdout.write(self.style.SUCCESS(f'Marked {app}.{migration} as applied'))
                else:
                    self.stdout.write(f'Migration {app}.{migration} is already marked as applied')
        
        self.stdout.write(self.style.SUCCESS('All specified migrations have been marked as applied'))
