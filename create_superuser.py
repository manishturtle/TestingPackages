import os
import django
from django.db import connection

# Set up Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "erp_project.settings")
django.setup()

# Import models after Django setup
from django.contrib.auth.models import User
from authentication.models import UserProfile

# Create a superuser in the public schema
try:
    # Check if user already exists
    if User.objects.filter(email='ankit@turtlesoftware.co').exists():
        user = User.objects.get(email='ankit@turtlesoftware.co')
        print(f"User already exists: {user.username}")
        
        # Update password
        user.set_password('Turtle@1981')
        user.save()
        print(f"Updated password for user: {user.username}")
    else:
        # Create new superuser
        user = User.objects.create_user(
            username='ankit@turtlesoftware.co',
            email='ankit@turtlesoftware.co',
            password='Turtle@1981',
            first_name='Ankit',
            last_name='Admin'
        )
        user.is_staff = True
        user.is_superuser = True
        user.save()
        print(f"Created superuser: {user.username}")
        
    # Create or update user profile
    try:
        profile = UserProfile.objects.get(user=user)
        profile.is_email_verified = True
        profile.save()
        print(f"Updated profile for {user.username}")
    except UserProfile.DoesNotExist:
        profile = UserProfile(
            user=user,
            is_email_verified=True
        )
        profile.save()
        print(f"Created profile for {user.username}")
    
    print("Superuser setup complete!")
    
except Exception as e:
    print(f"Error creating superuser: {str(e)}")
