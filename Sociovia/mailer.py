import smtplib
import ssl
from email.message import EmailMessage
from flask import current_app

def send_mail(to_addrs, subject, body):
    """
    Send email using SMTP configuration from Flask config
    """
    # Handle single email or list of emails
    if isinstance(to_addrs, str):
        to_addrs = [to_addrs]
    
    # Skip if no SMTP configuration
    if not current_app.config["SMTP_USER"] or not current_app.config["SMTP_PASS"]:
        print(f"Email would be sent to {to_addrs}: {subject}")
        print(f"Body: {body}")
        return
    
    try:
        # Create message
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = current_app.config["MAIL_FROM"]
        msg["To"] = ", ".join(to_addrs)
        msg.set_content(body)

        # Create secure connection and send
        context = ssl.create_default_context()
        
        with smtplib.SMTP(current_app.config["SMTP_HOST"], current_app.config["SMTP_PORT"]) as server:
            server.starttls(context=context)
            server.login("sociovia.ai@gmail.com", "dinm hrwm igpd sjyy")
            server.send_message(msg)
            
        print(f"Email sent successfully to {to_addrs}")
        
    except Exception as e:
        print(f"Failed to send email to {to_addrs}: {e}")
        raise
