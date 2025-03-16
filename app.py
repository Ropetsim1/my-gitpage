from flask import Flask, render_template, request, make_response, redirect, url_for
import base64
import json
import hashlib
import os

app = Flask(__name__)
#app.config['DEBUG'] = False

# Load accounts from JSON file and hash passwords with SHA-256
with open("myfile.json", "r") as out_file:
    accounts = json.load(out_file)

# Hash the passwords
for username, password in accounts.items():
    accounts[username] = hashlib.sha256(password.encode('utf-8')).hexdigest()

# Encryption function for the session token
def encrypt_session_token(data):
    salt = os.urandom(16)  # Generate a random 16-byte salt
    salted_data = salt + data.encode('utf-8')
    encrypted_data = hashlib.sha256(salted_data).digest()
    # Combine salt and encrypted data, then encode in Base64
    return base64.b64encode(salt + encrypted_data).decode('utf-8')

# Decrypt and verify the session token
def decrypt_session_token(encrypted_data, original_data):
    try:
        decoded_data = base64.b64decode(encrypted_data.encode('utf-8'))
        salt = decoded_data[:16]  # Extract the salt (first 16 bytes)
        encrypted_data = decoded_data[16:]  # Extract the actual encrypted part
        # Recreate the hashed data using the salt and original data
        expected_encrypted_data = hashlib.sha256(salt + original_data.encode('utf-8')).digest()
        return encrypted_data == expected_encrypted_data
    except Exception as e:
        print("Decryption error:", e)
        return False

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def handle_login():
    username = request.form.get('username')
    password = request.form.get('password')
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

    if username in accounts and accounts[username] == hashed_password:
        # Encrypt username into a secure session token
        session_token = encrypt_session_token(username)
        response = make_response(redirect(url_for('home')))  # Redirect to /home
        response.set_cookie('session_id', session_token)  # Store encrypted token as cookie
        return response
    else:
        return "Invalid username or password. Please try again."

@app.route("/")
def idk():
    return render_template("slash.html")

@app.route("/home")
def home():
    session_token = request.cookies.get('session_id')
    if session_token:
        # Decrypt the session token and verify it
        for username in accounts:
            if decrypt_session_token(session_token, username):
                return render_template("home.html", username=username)
        return "Invalid session token."
    return "You are not logged in. Please log in first."

@app.route('/logout')
def logout():
    # Create a response to redirect to the login page
    response = make_response(redirect(url_for('login')))
    # Clear the session cookie by setting its value to an empty string and its expiration time to the past
    response.set_cookie('session_id', '', expires=0)
    return response

# Set the upload folder path and allow specific file extensions
UPLOAD_FOLDER = 'static/uploads'  # Folder to save uploaded files
ALLOWED_EXTENSIONS = {"py", "zip"}  # Allowed file types

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Check if the file extension is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload')
def index():
    return render_template('upload.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    session_token = request.cookies.get('session_id')
    print("Session token from cookie:", session_token)  # Debugging
    if not session_token:
        return "You are not logged in."

    # Decrypt and validate the session token
    try:
        username = None
        for account_username in accounts:
            if decrypt_session_token(session_token, account_username):
                username = account_username
                break

        print("Decrypted username:", username)  # Debugging
    except Exception as e:
        print("Decryption error:", e)
        return "Invalid session token."

    if username != "Owner":
        return "Only 'Owner' is allowed to upload files."

    if 'file' not in request.files:
        return "No file part in the request."
    
    file = request.files['file']
    if file.filename == '':
        return "No selected file."

    if file and allowed_file(file.filename):
        filename = file.filename
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return f"File '{filename}' uploaded successfully!"
    
    return "File type not allowed."

if __name__ == '__main__':
    # Create the uploads folder if it doesn't exist
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True)
