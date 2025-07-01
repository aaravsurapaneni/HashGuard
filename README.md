# HashGuard – Secure Password Hasher Web App

HashGuard is a Flask-based web application that demonstrates **secure password hashing**, **user management**, and **algorithm comparison**.  

It’s designed to **educate users** about how modern hashing algorithms work, how to store passwords securely, and the differences between popular approaches like bcrypt, Argon2, and SHA-256.

---

## 🚀 Features

✅ **User Registration & Login**
- Register with a username and password.
- Choose hashing algorithm: bcrypt, Argon2, or SHA-256.
- Passwords are securely hashed before storage.
- Login verifies passwords against stored hashes.

✅ **Hash / Verify Tool**
- Generate a hash from any input password in real-time.
- Verify a password against a provided hash.

✅ **Password Strength Meter**
- Real-time feedback as you type.
- Indicates password strength from Weak to Very Strong.

✅ **Algorithm Comparison Tab**
- Enter a password once and see how bcrypt, Argon2, and SHA-256 hash it.
- Includes **detailed descriptions** of each algorithm’s strengths and weaknesses.
- Educational for understanding password security choices.

✅ **User Management**
- View all registered users (username + chosen algorithm).
- Admin-style delete button to remove users.

✅ **Responsive, Clean UI**
- Organized into tabs: Hash/Verify, Register/Login, Compare, and Users.
- Clear, modern styling with easy-to-use forms.

---

## 🔒 Why This Project?

HashGuard isn’t just a tool—it’s an **educational demo** designed to:

- Show how to hash passwords securely.
- Explain the *why* behind choosing certain algorithms.
- Help users understand best practices (salting, work factors, memory hardness).
- Make security concepts **accessible** with clear, side-by-side comparisons.

It's perfect for learning about **cryptography**, **secure authentication**, and **web security basics**.

---

## 🛠️ Tech Stack

- **Backend:** Python 3, Flask
- **Hashing Libraries:** bcrypt, argon2-cffi, hashlib
- **Frontend:** HTML, CSS, JavaScript (vanilla)
- **Templating:** Jinja2
- **Version Control:** Git, GitHub

---

## 💻 Getting Started

### 🔹 Clone the repository

```bash
git clone https://github.com/Codeneze/HashGuard.git
cd HashGuard
