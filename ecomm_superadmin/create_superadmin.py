from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from django.db import transaction


class Command(BaseCommand):
    help = 'Creates a superadmin user with specified username and password'

    def add_arguments(self, parser):
        parser.add_argument('--username', type=str, default='superadmin', help='Username for the superadmin')
        parser.add_argument('--email', type=str, default='admin@example.com', help='Email for the superadmin')
        parser.add_argument('--password', type=str, help='Password for the superadmin (if not provided, will prompt)')

    def handle(self, *args, **options):
        username = options['username']
        email = options['email']
        password = options['password']

        # Check if user already exists
        if User.objects.filter(username=username).exists():
            self.stdout.write(self.style.WARNING(f'User with username "{username}" already exists'))
            return

        # If password not provided, prompt for it
        if not password:
            from getpass import getpass
            password = getpass('Password: ')
            password_confirm = getpass('Password (again): ')
            if password != password_confirm:
                self.stderr.write(self.style.ERROR('Passwords do not match'))
                return

        try:
            with transaction.atomic():
                # Create the superuser
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=password
                )
                user.is_staff = True
                user.is_superuser = True
                user.save()

                self.stdout.write(self.style.SUCCESS(f'Superadmin "{username}" created successfully'))
        except Exception as e:
            self.stderr.write(self.style.ERROR(f'Failed to create superadmin: {str(e)}'))
