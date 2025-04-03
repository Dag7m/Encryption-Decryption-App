# Encryption/Decryption Application

A Django-based web application that demonstrates various encryption and decryption techniques including OTP, AES, 3DES, and RSA.

## Features

- **One-Time Pad (OTP)**: Perfect secrecy with one-time pad encryption
- **AES (Advanced Encryption Standard)**: Industry-standard symmetric encryption with 256-bit keys
- **3DES (Triple DES)**: Legacy symmetric encryption used in financial systems
- **RSA**: Public-key cryptography with 2048-bit keys for secure asymmetric encryption

## Screenshots

[You can add screenshots of your application here]

## Installation

1. Clone the repository: git clone https://github.com/Dag7m/encryption-decryption-app.git then cd encryption-decryption-app

2. Create and activate a virtual environment: python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
  
3. Install dependencies: pip install -r requirements.txt

4. Run migrations: python manage.py migrate
5. Start the development server: python manage.py runserver
6. Open your browser and navigate to `http://127.0.0.1:8000/`

## Usage

### OTP Encryption
1. Generate a new OTP key
2. Enter the text you want to encrypt
3. Use the same key for decryption

### AES Encryption
1. Generate a new AES key and IV
2. Enter the text you want to encrypt
3. Use the same key and IV for decryption

### 3DES Encryption
1. Generate a new 3DES key
2. Enter the text you want to encrypt
3. Use the same key for decryption

### RSA Encryption
1. Generate a new pair of RSA keys (public and private)
2. Use the public key to encrypt your message
3. Use the private key to decrypt the message

## Security Notice

This application is for educational purposes only. In a production environment, additional security measures would be necessary.



## Author

Dagem Girum
