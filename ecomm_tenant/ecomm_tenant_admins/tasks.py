from celery import shared_task
from django.db import connection
from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from .models import UserProfile, TenantUser
from ecomm_superadmin.models import Tenant
import logging

logger = logging.getLogger(__name__)

@shared_task
def send_tenant_admin_credentials(email, password, tenant_name, url_suffix):
    """
    Send email with login credentials to the newly created tenant admin.
    
    Args:
        email (str): The email address of the tenant admin
        password (str): The generated password (if auto-generated)
        tenant_name (str): The name of the tenant
        url_suffix (str): The URL suffix of the tenant
    """
    subject = f"Welcome to {tenant_name} - Your Admin Account Details"
    
    # Construct the tenant URL
    tenant_url = f"https://{url_suffix}.example.com" if url_suffix else f"https://{tenant_name.lower().replace(' ', '-')}.example.com"
    
    message = f"""
Hello,

Your tenant has been successfully created in our SaaS ERP system.

Tenant Details:
- Name: {tenant_name}
- URL: {tenant_url}

Your admin account has been set up with the following credentials:
- Email: {email}
- Password: {password}

Please log in and change your password immediately.

Thank you for choosing our platform!

Best regards,
The Turtle ERP Team
"""
    
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
        )
        logger.info(f"Admin credentials email sent to {email} for tenant {tenant_name}")
        return True
    except Exception as e:
        logger.error(f"Failed to send admin credentials email to {email}: {str(e)}")
        return False

@shared_task
def send_tenant_admin_welcome_email(user_id, password=None):
    """
    Send a welcome email to the newly created tenant admin.
    
    Args:
        user_id (int): The ID of the tenant admin user
        password (str, optional): The auto-generated password, if applicable
        
    Returns:
        bool: True if the email was sent successfully, False otherwise
    """
    try:
        # Get the user
        user = User.objects.get(id=user_id)
        
        # Get the user profile
        try:
            profile = UserProfile.objects.get(user=user)
        except UserProfile.DoesNotExist:
            logger.error(f"UserProfile not found for user {user_id}")
            return False
        
        # Check if this is a tenant admin
        if not profile.is_tenant_admin:
            logger.warning(f"User {user_id} is not a tenant admin, skipping welcome email")
            return False
        
        # Get the tenant (client)
        # Since we're in a tenant schema, we need to get the tenant from the connection
        from django.db import connection
        tenant_schema_name = connection.schema_name
        
        try:
            tenant = Tenant.objects.get(schema_name=tenant_schema_name)
        except Tenant.DoesNotExist:
            logger.error(f"Tenant not found for schema {tenant_schema_name}")
            return False
        
        # Construct the tenant URL
        if tenant.custom_domain:
            tenant_url = f"https://{tenant.custom_domain}"
        else:
            url_suffix = tenant.schema_name
            tenant_url = settings.BASE_TENANT_URL.format(url_suffix)
        
        # Prepare context for the email template
        context = {
            'user': user,
            'tenant': tenant,
            'tenant_name': tenant.name,
            'tenant_url': tenant_url,
            'password': password,
        }
        
        # Send the email using the template
        subject = f"Welcome to {tenant.name} - Your Admin Account"
        result = send_template_email(
            to_email=user.email,
            subject=subject,
            template_name='tenant_admin_welcome',
            context=context
        )
        
        if result['status'] == 'success':
            logger.info(f"Welcome email sent to tenant admin {user.email} for tenant {tenant.name}")
            return True
        else:
            logger.error(f"Failed to send welcome email to tenant admin {user.email}: {result['message']}")
            return False
            
    except User.DoesNotExist:
        logger.error(f"User not found with ID {user_id}")
        return False
    except Exception as e:
        logger.exception(f"Error sending welcome email to tenant admin (user_id={user_id}): {str(e)}")
        return False

@shared_task
def send_new_tenant_user_welcome_email(user_id, generated_password=None):
    """
    Send a welcome email to a newly created tenant user.
    
    Args:
        user_id (int): The ID of the tenant user
        generated_password (str, optional): The auto-generated password, if applicable
        
    Returns:
        bool: True if the email was sent successfully, False otherwise
    """
    from django.db import connection
    
    try:
        # Get the tenant user
        user = TenantUser.objects.get(id=user_id)
        
        # Get the tenant name from the connection
        tenant_name = connection.tenant.name if hasattr(connection, 'tenant') else "Your Organization"
        
        subject = f"Welcome to {tenant_name} - Your Account Details"
        
        # Construct the tenant URL based on the current connection
        tenant_url = f"https://{connection.tenant.url_suffix}.example.com" if hasattr(connection, 'tenant') and connection.tenant.url_suffix else "https://app.example.com"
        
        # Prepare the context for the email template
        context = {
            'user': user,
            'tenant_name': tenant_name,
            'tenant_url': tenant_url,
            'generated_password': generated_password,
            'has_generated_password': generated_password is not None
        }
        
        # Try to use the template-based email if available
        try:
            html_message = render_to_string('emails/new_tenant_user_welcome.html', context)
            plain_message = strip_tags(html_message)
            
            # Try to use the custom email sender if available
            try:
                send_template_email(
                    recipient_email=user.email,
                    subject=subject,
                    template_name='new_tenant_user_welcome',
                    context=context
                )
            except Exception as e:
                logger.warning(f"Failed to send template email: {str(e)}. Falling back to standard email.")
                # Fall back to standard email
                send_mail(
                    subject=subject,
                    message=plain_message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.email],
                    html_message=html_message,
                    fail_silently=False
                )
        except Exception as e:
            logger.warning(f"Failed to render email template: {str(e)}. Falling back to plain text email.")
            
            # Fall back to plain text email
            message = f"""
Hello {user.first_name},

Welcome to {tenant_name}! Your account has been created successfully.

Your account details:
- Email: {user.email}
"""
            
            # Add password information if it was auto-generated
            if generated_password:
                message += f"""- Password: {generated_password}

Please log in and change your password immediately for security reasons.
"""
            else:
                message += """
Please use the password you were provided separately or use the password reset function if needed.
"""
            
            message += f"""
You can access the platform at: {tenant_url}

Thank you for joining us!

Best regards,
The {tenant_name} Team
"""
            
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False
            )
        
        logger.info(f"Welcome email sent to tenant user {user.email}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send welcome email to tenant user: {str(e)}")
        return False
