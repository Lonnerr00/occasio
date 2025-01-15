from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from pymongo import MongoClient, server_api
import os
import random
import json
from smtplib import SMTP

# Load environment variables
load_dotenv()
EMAIL_USER = os.getenv('EMAIL_USER')
EMAIL_PASS = os.getenv('EMAIL_PASS')
mongo_pass = os.getenv('mongo_pass')
mongo_user = os.getenv('mongo_user')
MONGO_URI = mongo_uri=f'mongodb+srv://{mongo_user}:{mongo_pass}@cluster0.vqfml.mongodb.net/'


# Initialize Flask app
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# MongoDB client setup
client = MongoClient(MONGO_URI, server_api=server_api.ServerApi('1'))
try:
    client.admin.command('ping')
    print("Pinged your deployment. Successfully connected to MongoDB!")
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")

db = client['Occasio_EventReminder']
user_collection = db['UsersList']

# Email credentials
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587

# JSON file to store local data
DATA_FILE = 'data.json'

# Utility Functions
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as file:
            return json.load(file)
    return {}

def save_data(data):
    with open(DATA_FILE, 'w') as file:
        json.dump(data, file, indent=4)

def sync_with_mongo():
    """Synchronize local JSON with MongoDB."""
    users = list(user_collection.find({}, {"_id": 0}))
    save_data({user['email']: user for user in users})

def generate_otp():
    return str(random.randint(100000, 999999))

@app.route('/')
def home():
    return 'Welcome to the Flask API!'

@app.route('/signup', methods=['POST'])
def signup():
    print("signup")

    data = request.json
    email = data.get('email')
    name = data.get('name')
    password = data.get('password')
    otp = generate_otp()
    
    try:
        # Send OTP via email
        with SMTP(EMAIL_HOST, EMAIL_PORT) as smtp:
            smtp.starttls()
            smtp.login(EMAIL_USER, EMAIL_PASS)
            smtp.sendmail(EMAIL_USER, email, f"Subject: Signup OTP\n\nYour OTP is {otp}")
        # Store user details and OTP in MongoDB
        user = {'email': email, 'name': name, 'password': password, 'otp': otp}
        user_collection.replace_one({'email': email}, user, upsert=True)

        # Sync with local JSON
        sync_with_mongo()

        return jsonify({'message': 'Signup successful. OTP sent!'}), 201
    except Exception as e:
        return jsonify({'message': 'Signup failed.', 'error': str(e)}), 500

@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    data = request.json
    email = data.get('email')
    otp = generate_otp()

    try:
        # Find user in MongoDB
        return jsonify({'User Data': user_collection}), 200
        user = user_collection.find_one({'email': email})
        if not user:
            return jsonify({'message': 'Email not found.'}), 404

        # Send OTP via email
        with SMTP(EMAIL_HOST, EMAIL_PORT) as smtp:
            smtp.starttls()
            smtp.login(EMAIL_USER, EMAIL_PASS)
            smtp.sendmail(EMAIL_USER, email, f"Subject: Resend OTP\n\nYour OTP is {otp}")

        # Update OTP in MongoDB
        user_collection.update_one({'email': email}, {'$set': {'otp': otp}})

        # Sync with local JSON
        sync_with_mongo()

        return jsonify({'message': 'OTP resent successfully.'}), 200
    except Exception as e:
        return jsonify({'message': 'Failed to resend OTP.', 'error': str(e)}), 500

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.json
    email = data.get('email')
    otp = data.get('otp')

    try:
        # Find user in MongoDB
        user = user_collection.find_one({'email': email})
        if not user:
            return jsonify({'message': 'Email not found.'}), 404

        # Check if OTP matches
        if user['otp'] == otp:
            return jsonify({'message': 'OTP verified successfully.'}), 200
        else:
            return jsonify({'message': 'Invalid OTP.'}), 400
    except Exception as e:
        return jsonify({'message': 'Failed to verify OTP.', 'error': str(e)}), 500

if __name__ == '__main__':
    # Sync local JSON with MongoDB on startup
    sync_with_mongo()
    app.run(host='0.0.0.0', port=5000, debug=True)
