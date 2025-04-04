"""
Management command to generate a Fernet key for encryption.
"""
from django.core.management.base import BaseCommand
from authentication.utils import generate_fernet_key


class Command(BaseCommand):
    help = 'Generate a secure Fernet key for encryption'

    def handle(self, *args, **options):
        """
        Generate and display a secure Fernet key.
        """
        key = generate_fernet_key()
        
        self.stdout.write(self.style.SUCCESS(
            f"\nGenerated Fernet Key: {key}\n"
        ))
        
        self.stdout.write(
            "\nTo use this key, set it as an environment variable:\n"
            "- For Windows (PowerShell):\n"
            f'  $env:FERNET_KEY = "{key}"\n'
            "- For Windows (Command Prompt):\n"
            f'  set FERNET_KEY={key}\n'
            "- For Linux/macOS:\n"
            f'  export FERNET_KEY="{key}"\n'
            "\nFor production, add this to your environment variables or .env file.\n"
        )
