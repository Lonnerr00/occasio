from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
from datetime import datetime, timedelta
import random
import jwt
import bleach

EMAIL_USER = os.getenv('EMAIL_USER')
EMAIL_PASS = os.getenv('EMAIL_PASS')
SECRET_KEY = os.getenv('SECRET_KEY')

def generate_signup_body(email, otp):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_USER
    msg['To'] = email
    msg['Subject'] = "Welcome to Occasio - Your Signup OTP"

    body = f"""
    <html>
    <body>
        <div style="font-family: Arial, sans-serif; color: #333;">
            <h2>Welcome to Occasio!</h2>
            <p>Dear User,</p>
            <p>Thank you for signing up for Occasio. To complete your registration, please use the following OTP:</p>
            <h3 style="color: #2E86C1;">{otp}</h3>
            <p>This OTP is valid for the next 10 minutes. Please do not share this OTP with anyone.</p>
            <p>If you did not request this, please ignore this email.</p>
            <br>
            <p>Best regards,</p>
            <p>The Occasio Team</p>
            <hr>
            <p style="font-size: 12px; color: #777;">
                <a href="mailto:support@occasio.com">support@occasio.com</a><br>
                <a href="https://www.occasio.com">www.occasio.com</a>
            </p>
        </div>
    </body>
    </html>
    """
    msg.attach(MIMEText(body, 'html'))
    return msg

def generate_reset_body(email, otp):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_USER
    msg['To'] = email
    msg['Subject'] = "Welcome to Occasio - Your Signup OTP"

    body = f"""
    <html>
    <body>
        <div style="font-family: Arial, sans-serif; color: #333;">
            <h2>Password Reset Request</h2>
            <p>Dear User,</p>
            <p>We received a request to reset your password for your Occasio account. Please use the following OTP to reset your password:</p>
            <h3 style="color: #2E86C1;">{otp}</h3>
            <p>This OTP is valid for the next 10 minutes. If you did not request a password reset, please ignore this email.</p>
            <br>
            <p>Best regards,</p>
            <p>The Occasio Team</p>
            <hr>
            <p style="font-size: 12px; color: #777;">
                <a href="mailto:support@occasio.com">support@occasio.com</a><br>
                <a href="https://www.occasio.com">www.occasio.com</a>
            </p>
        </div>
    </body>
    </html>
    """
    msg.attach(MIMEText(body, 'html'))
    return msg



# Function to generate OTP with expiry
def generate_otp():
    otp = str(random.randint(100000, 999999))
    expiry_time = datetime.utcnow() + timedelta(minutes=5)  # OTP expires in 5 minutes
    return otp, expiry_time

# Generate JWT token
def generate_token(email):
    payload = {
        'email': email,
        'exp': datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token

# Function to sanitize inputs
def sanitize_input(data):
    if not isinstance(data, str):
        return data
    return bleach.clean(data)