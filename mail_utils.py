import random

from flask_mail import Message


def generate_otp():
    """
    Generate a random 6-digit OTP.
    """
    return str(random.randint(100000, 999999))


def send_otp_email(mail, recipient_email, otp):
    """
    Send an OTP verification email.
    """

    msg = Message(
        subject="Security Monitoring System - Email Verification OTP",
        recipients=[recipient_email]
    )

    msg.body = f"""
Hello,

Your One-Time Password (OTP) is:

{otp}

This code will expire in 10 minutes.

If you did not request this code, please ignore this email.

Regards,
Security Monitoring System
"""

    mail.send(msg)