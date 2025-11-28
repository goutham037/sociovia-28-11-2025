import os
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv

# Load .env
load_dotenv()

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))

# Support both naming conventions
SMTP_USERNAME = os.getenv("SMTP_USERNAME") or os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD") or os.getenv("SMTP_PASS")
SMTP_FROM = os.getenv("SMTP_FROM") or os.getenv("MAIL_FROM") or SMTP_USERNAME

print("HOST:", SMTP_HOST)
print("PORT:", SMTP_PORT)
print("USER:", SMTP_USERNAME)
print("FROM:", SMTP_FROM)

if not SMTP_USERNAME or not SMTP_PASSWORD:
    raise RuntimeError("SMTP_USERNAME/SMTP_USER or SMTP_PASSWORD/SMTP_PASS not set in .env")

msg = EmailMessage()
msg["Subject"] = "Sociovia SMTP Test"
msg["From"] = SMTP_FROM
msg["To"] = SMTP_USERNAME  # send to yourself
msg.set_content("If you see this, SMTP is working.")

with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
    server.starttls()
    server.login(SMTP_USERNAME, SMTP_PASSWORD)
    server.send_message(msg)

print("Sent!")
