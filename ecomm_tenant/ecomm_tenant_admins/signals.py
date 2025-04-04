from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.hashers import make_password
from django.db import connection
from django.utils.crypto import get_random_string

# This file will contain signal handlers for tenant-related operations
