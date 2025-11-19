# utils/email_sender.py
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import render_template_string
import logging
from config import config

logger = logging.getLogger("email_sender")

class EmailSender:
    def __init__(self):
        self.mail_server = config.MAIL_SERVER
        self.mail_port = config.EMAIL_PORT
        self.mail_username = config.MAIL_USERNAME
        self.mail_password = config.MAIL_PASSWORD
        self.mail_sender = config.MAIL_DEFAULT_SENDER
    
    def send_email(self, to_email, subject, html_content, text_content=None):
        """
        Send email using SMTP
        
        Args:
            to_email: Recipient email address
            subject: Email subject
            html_content: HTML content of the email
            text_content: Plain text content (optional, will be generated from HTML if not provided)
        """
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.mail_sender
            msg['To'] = to_email
            
            # Create plain text version if not provided
            if not text_content:
                # Simple HTML to text conversion
                import re
                text_content = re.sub('<[^<]+?>', '', html_content)
                text_content = re.sub('\n+', '\n', text_content).strip()
            
            # Attach both HTML and plain text versions
            part1 = MIMEText(text_content, 'plain')
            part2 = MIMEText(html_content, 'html')
            
            msg.attach(part1)
            msg.attach(part2)
            
            # Send email
            with smtplib.SMTP(self.mail_server, self.mail_port) as server:
                server.starttls()  # Enable security
                server.login(self.mail_username, self.mail_password)
                server.send_message(msg)
            
            logger.info(f"✓ Email sent successfully to {to_email}")
            return True
            
        except Exception as e:
            logger.error(f"✗ Failed to send email to {to_email}: {str(e)}")
            return False

# Create a global instance
email_sender = EmailSender()