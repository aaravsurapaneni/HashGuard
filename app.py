from flask import Flask, render_template, request
import bcrypt
import hashlib
from argon2 import PasswordHasher
import json
import os

app = Flask(__name__)
ph = PasswordHasher()

USERS_FILE = 'users.json'

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def hash_bcrypt(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()

def verify_bcrypt(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

def hash_argon2(password):
    return ph.hash(password)

def verify_argon2(password, hashed):
    return ph.verify(hashed, password)

def hash_sha256(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    selected_algo = None
    compare_results = None
    users = load_users()

    if request.method == 'POST':
        action = request.form.get('action')
        username = request.form.get('username')
        password = request.form.get('password')
        stored_hash = request.form.get('stored_hash')
        selected_algo = request.form.get('algorithm')

        if action == 'register':
            if not username or not password or not selected_algo:
                result = "❌ Please enter username, password, and select algorithm."
            elif username in users:
                result = f"❌ Username '{username}' already exists."
            else:
                if selected_algo == 'bcrypt':
                    hashed = hash_bcrypt(password)
                elif selected_algo == 'argon2':
                    hashed = hash_argon2(password)
                elif selected_algo == 'sha256':
                    hashed = hash_sha256(password)
                else:
                    hashed = None

                if hashed:
                    users[username] = {
                        'hash': hashed,
                        'algorithm': selected_algo
                    }
                    save_users(users)
                    result = f"✅ User '{username}' registered successfully with {selected_algo}."

        elif action == 'login':
            if not username or not password:
                result = "❌ Please enter username and password to login."
            elif username not in users:
                result = f"❌ Username '{username}' not found."
            else:
                stored = users[username]
                algo = stored['algorithm']
                stored_hash = stored['hash']
                try:
                    if algo == 'bcrypt':
                        if verify_bcrypt(password, stored_hash):
                            result = "✅ Login successful!"
                        else:
                            result = "❌ Incorrect password."
                    elif algo == 'argon2':
                        if verify_argon2(password, stored_hash):
                            result = "✅ Login successful!"
                        else:
                            result = "❌ Incorrect password."
                    elif algo == 'sha256':
                        if hash_sha256(password) == stored_hash:
                            result = "✅ Login successful!"
                        else:
                            result = "❌ Incorrect password."
                    else:
                        result = "❌ Unsupported algorithm."
                except Exception:
                    result = "❌ Invalid hash format or error during verification."

        elif action == 'hash':
            if not password or not selected_algo:
                result = "❌ Please enter password and select algorithm."
            else:
                if selected_algo == 'bcrypt':
                    hashed = hash_bcrypt(password)
                    result = f"bcrypt Hash: {hashed}"
                elif selected_algo == 'argon2':
                    hashed = hash_argon2(password)
                    result = f"Argon2 Hash: {hashed}"
                elif selected_algo == 'sha256':
                    hashed = hash_sha256(password)
                    result = f"SHA-256 Hash: {hashed}"
                else:
                    result = "❌ Please select a valid algorithm."

        elif action == 'verify':
            if not password or not stored_hash or not selected_algo:
                result = "❌ Please enter password, stored hash, and select algorithm."
            else:
                try:
                    if selected_algo == 'bcrypt':
                        if verify_bcrypt(password, stored_hash):
                            result = "✅ Password matches!"
                        else:
                            result = "❌ Password does NOT match."
                    elif selected_algo == 'argon2':
                        if verify_argon2(password, stored_hash):
                            result = "✅ Password matches!"
                        else:
                            result = "❌ Password does NOT match."
                    elif selected_algo == 'sha256':
                        if hash_sha256(password) == stored_hash:
                            result = "✅ Password matches!"
                        else:
                            result = "❌ Password does NOT match."
                    else:
                        result = "❌ Unsupported algorithm."
                except Exception:
                    result = "❌ Invalid hash format or error during verification."

        elif action == 'delete':
            username_to_delete = request.form.get('delete_user')
            if username_to_delete in users:
                del users[username_to_delete]
                save_users(users)
                result = f"✅ User '{username_to_delete}' deleted."

        elif action == 'compare':
            if not password:
                result = "❌ Please enter a password to compare."
            else:
                compare_results = {
                    'bcrypt': hash_bcrypt(password),
                    'argon2': hash_argon2(password),
                    'sha256': hash_sha256(password)
                }

        users = load_users()

    return render_template('index.html', result=result, selected_algo=selected_algo, users=users, compare_results=compare_results)

if __name__ == "__main__":
    app.run(debug=True)
