import requests
import json
import logging
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags

logger = logging.getLogger(__name__)

class ZeptoMailClient:
    """
    Client for sending emails using Zoho ZeptoMail API.
    """
    
    def __init__(self):
        self.api_key = getattr(settings, 'ZEPTOMAIL_API_KEY', '')
        self.base_url = getattr(settings, 'ZEPTOMAIL_API_URL', 'https://api.zeptomail.com/v1.1/email')
        self.from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@saas-erp.com')
        self.from_name = getattr(settings, 'DEFAULT_FROM_NAME', 'SaaS ERP')
        
        if not self.api_key:
            logger.warning("ZeptoMail API key not configured. Emails will not be sent.")
    
    def send_email(self, to_email, subject, html_content, text_content=None, reply_to=None):
        """
        Send an email using the ZeptoMail API.
        
        Args:
            to_email (str): Recipient email address
            subject (str): Email subject
            html_content (str): HTML content of the email
            text_content (str, optional): Plain text content of the email
            reply_to (str, optional): Reply-to email address
            
        Returns:
            dict: API response or error message
        """
        if not self.api_key:
            logger.error("ZeptoMail API key not configured. Email not sent.")
            return {"status": "error", "message": "ZeptoMail API key not configured"}
        
        # If text_content is not provided, strip HTML tags from html_content
        if text_content is None:
            text_content = strip_tags(html_content)
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Zoho-enczapikey {self.api_key}"
        }
        
        payload = {
            "from": {
                "address": self.from_email,
                "name": self.from_name
            },
            "to": [
                {
                    "email_address": {
                        "address": to_email
                    }
                }
            ],
            "subject": subject,
            "htmlbody": html_content,
            "textbody": text_content
        }
        
        if reply_to:
            payload["reply_to"] = {
                "address": reply_to
            }
        
        try:
            response = requests.post(
                self.base_url,
                headers=headers,
                data=json.dumps(payload)
            )
            
            if response.status_code in (200, 201, 202):
                logger.info(f"Email sent successfully to {to_email}")
                return {"status": "success", "data": response.json()}
            else:
                logger.error(f"Failed to send email to {to_email}. Status code: {response.status_code}. Response: {response.text}")
                return {"status": "error", "message": f"API error: {response.text}"}
                
        except Exception as e:
            logger.exception(f"Exception when sending email to {to_email}: {str(e)}")
            return {"status": "error", "message": str(e)}

def send_template_email(to_email, subject, template_name, context, reply_to=None):
    """
    Send an email using a template.
    
    Args:
        to_email (str): Recipient email address
        subject (str): Email subject
        template_name (str): Name of the template (without extension)
        context (dict): Context data for the template
        reply_to (str, optional): Reply-to email address
        
    Returns:
        dict: API response or error message
    """
    # Render HTML template
    html_template = f"emails/{template_name}.html"
    html_content = render_to_string(html_template, context)
    
    # Render text template
    text_template = f"emails/{template_name}.txt"
    try:
        text_content = render_to_string(text_template, context)
    except:
        # If text template doesn't exist, strip HTML tags from HTML content
        text_content = strip_tags(html_content)
    
    # Send email
    client = ZeptoMailClient()
    return client.send_email(to_email, subject, html_content, text_content, reply_to)
