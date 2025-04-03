from django.shortcuts import render, redirect
import base64
import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

# Function to generate a random key for OTP
def generate_otp_key(length=16):
    return base64.b64encode(os.urandom(length)).decode('utf-8')

# Function to perform OTP encryption
def encrypt_otp(plaintext, key):
    # Convert key and plaintext to bytes
    key_bytes = key.encode('utf-8')
    plaintext_bytes = plaintext.encode('utf-8')
    
    # Ensure key is at least as long as plaintext
    while len(key_bytes) < len(plaintext_bytes):
        key_bytes += key_bytes
    
    # Truncate key to match plaintext length
    key_bytes = key_bytes[:len(plaintext_bytes)]
    
    # XOR operation
    encrypted_bytes = bytes([p ^ k for p, k in zip(plaintext_bytes, key_bytes)])
    
    # Return base64 encoded result
    return base64.b64encode(encrypted_bytes).decode('utf-8')

# Function to perform OTP decryption (same as encryption for OTP)
def decrypt_otp(ciphertext, key):
    try:
        # Decode base64 ciphertext
        ciphertext_bytes = base64.b64decode(ciphertext)
        
        # Convert key to bytes
        key_bytes = key.encode('utf-8')
        
        # Ensure key is at least as long as ciphertext
        while len(key_bytes) < len(ciphertext_bytes):
            key_bytes += key_bytes
        
        # Truncate key to match ciphertext length
        key_bytes = key_bytes[:len(ciphertext_bytes)]
        
        # XOR operation (same as encryption)
        decrypted_bytes = bytes([c ^ k for c, k in zip(ciphertext_bytes, key_bytes)])
        
        # Return decoded result
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        return f"Decryption error: {str(e)}"

# Function to generate a key for AES
def generate_aes_key():
    # Generate a random 32-byte key (256 bits)
    key = os.urandom(32)
    # Generate a random 16-byte IV
    iv = os.urandom(16)
    return {
        'key': base64.b64encode(key).decode('utf-8'),
        'iv': base64.b64encode(iv).decode('utf-8')
    }

# Function to perform AES encryption
def encrypt_aes(plaintext, key_b64, iv_b64):
    try:
        # Decode base64 key and IV
        key = base64.b64decode(key_b64)
        iv = base64.b64decode(iv_b64)
        
        # Create AES cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Pad the plaintext to be a multiple of 16 bytes (AES block size)
        padded_data = pad(plaintext.encode('utf-8'), 16)
        
        # Encrypt the data
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return base64 encoded result
        return base64.b64encode(ciphertext).decode('utf-8')
    except Exception as e:
        return f"Encryption error: {str(e)}"

# Function to perform AES decryption
def decrypt_aes(ciphertext, key_b64, iv_b64):
    try:
        # Decode base64 key, IV, and ciphertext
        key = base64.b64decode(key_b64)
        iv = base64.b64decode(iv_b64)
        ciphertext_bytes = base64.b64decode(ciphertext)
        
        # Create AES cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        
        # Decrypt the data
        padded_plaintext = decryptor.update(ciphertext_bytes) + decryptor.finalize()
        
        # Unpad the result
        plaintext = unpad(padded_plaintext, 16)
        
        # Return decoded result
        return plaintext.decode('utf-8')
    except Exception as e:
        return f"Decryption error: {str(e)}"

# Function to generate a key for 3DES
def generate_3des_key():
    # Generate a random 24-byte key (192 bits)
    key = DES3.adjust_key_parity(os.urandom(24))
    return base64.b64encode(key).decode('utf-8')

# Function to perform 3DES encryption
def encrypt_3des(plaintext, key_b64):
    try:
        # Decode base64 key
        key = base64.b64decode(key_b64)
        
        # Create 3DES cipher
        cipher = DES3.new(key, DES3.MODE_CBC)
        
        # Pad the plaintext to be a multiple of 8 bytes (3DES block size)
        padded_data = pad(plaintext.encode('utf-8'), 8)
        
        # Encrypt the data
        ciphertext = cipher.iv + cipher.encrypt(padded_data)
        
        # Return base64 encoded result
        return base64.b64encode(ciphertext).decode('utf-8')
    except Exception as e:
        return f"Encryption error: {str(e)}"

# Function to perform 3DES decryption
def decrypt_3des(ciphertext, key_b64):
    try:
        # Decode base64 key and ciphertext
        key = base64.b64decode(key_b64)
        ciphertext_bytes = base64.b64decode(ciphertext)
        
        # Extract IV (first 8 bytes) and actual ciphertext
        iv = ciphertext_bytes[:8]
        actual_ciphertext = ciphertext_bytes[8:]
        
        # Create 3DES cipher
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        
        # Decrypt the data
        padded_plaintext = cipher.decrypt(actual_ciphertext)
        
        # Unpad the result
        plaintext = unpad(padded_plaintext, 8)
        
        # Return decoded result
        return plaintext.decode('utf-8')
    except Exception as e:
        return f"Decryption error: {str(e)}"

# Function to generate RSA keys
def generate_rsa_keys():
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Get the public key
    public_key = private_key.public_key()
    
    # Serialize private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    # Serialize public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_pem, public_pem

# Function to perform RSA encryption
def encrypt_rsa(public_key_pem, plaintext):
    # Load the public key
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8')
    )
    
    # Encrypt the plaintext
    ciphertext = public_key.encrypt(
        plaintext.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Return base64 encoded ciphertext
    return base64.b64encode(ciphertext).decode('utf-8')

# Function to perform RSA decryption
def decrypt_rsa(private_key_pem, ciphertext_b64):
    try:
        # Load the private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None
        )
        
        # Decode the base64 ciphertext
        ciphertext = base64.b64decode(ciphertext_b64)
        
        # Decrypt the ciphertext
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return plaintext.decode('utf-8')
    except Exception as e:
        return f"Decryption error: {str(e)}"

# Main view for the home page
def index(request):
    return render(request, 'crypto_app/index.html')

# View for OTP encryption/decryption
def otp(request):
    context = {
        'encrypted_text': '',
        'decrypted_text': '',
        'key': '',
        'original_text': '',
        'encryption_method': 'otp'
    }
    
    if request.method == 'POST':
        action = request.POST.get('action', '')
        
        if action == 'generate_key':
            # Generate a new OTP key
            context['key'] = generate_otp_key()
            
        elif action == 'encrypt':
            # Get the text to encrypt and the key
            text_to_encrypt = request.POST.get('text_to_encrypt', '')
            key = request.POST.get('key', '')
            
            if text_to_encrypt and key:
                try:
                    encrypted_text = encrypt_otp(text_to_encrypt, key)
                    context['encrypted_text'] = encrypted_text
                    context['original_text'] = text_to_encrypt
                    context['key'] = key
                except Exception as e:
                    context['error'] = f"Encryption error: {str(e)}"
            
        elif action == 'decrypt':
            # Get the text to decrypt and the key
            text_to_decrypt = request.POST.get('text_to_decrypt', '')
            key = request.POST.get('key', '')
            
            if text_to_decrypt and key:
                try:
                    decrypted_text = decrypt_otp(text_to_decrypt, key)
                    context['decrypted_text'] = decrypted_text
                    context['encrypted_text'] = text_to_decrypt
                    context['key'] = key
                except Exception as e:
                    context['error'] = f"Decryption error: {str(e)}"
    
    return render(request, 'crypto_app/otp.html', context)

# View for AES encryption/decryption
def aes(request):
    context = {
        'encrypted_text': '',
        'decrypted_text': '',
        'key': '',
        'iv': '',
        'original_text': '',
        'encryption_method': 'aes'
    }
    
    if request.method == 'POST':
        action = request.POST.get('action', '')
        
        if action == 'generate_key':
            # Generate a new AES key
            aes_key = generate_aes_key()
            context['key'] = aes_key['key']
            context['iv'] = aes_key['iv']
            
        elif action == 'encrypt':
            # Get the text to encrypt, key, and IV
            text_to_encrypt = request.POST.get('text_to_encrypt', '')
            key = request.POST.get('key', '')
            iv = request.POST.get('iv', '')
            
            if text_to_encrypt and key and iv:
                try:
                    encrypted_text = encrypt_aes(text_to_encrypt, key, iv)
                    context['encrypted_text'] = encrypted_text
                    context['original_text'] = text_to_encrypt
                    context['key'] = key
                    context['iv'] = iv
                except Exception as e:
                    context['error'] = f"Encryption error: {str(e)}"
            
        elif action == 'decrypt':
            # Get the text to decrypt, key, and IV
            text_to_decrypt = request.POST.get('text_to_decrypt', '')
            key = request.POST.get('key', '')
            iv = request.POST.get('iv', '')
            
            if text_to_decrypt and key and iv:
                try:
                    decrypted_text = decrypt_aes(text_to_decrypt, key, iv)
                    context['decrypted_text'] = decrypted_text
                    context['encrypted_text'] = text_to_decrypt
                    context['key'] = key
                    context['iv'] = iv
                except Exception as e:
                    context['error'] = f"Decryption error: {str(e)}"
    
    return render(request, 'crypto_app/aes.html', context)

# View for 3DES encryption/decryption
def triple_des(request):
    context = {
        'encrypted_text': '',
        'decrypted_text': '',
        'key': '',
        'original_text': '',
        'encryption_method': '3des'
    }
    
    if request.method == 'POST':
        action = request.POST.get('action', '')
        
        if action == 'generate_key':
            # Generate a new 3DES key
            context['key'] = generate_3des_key()
            
        elif action == 'encrypt':
            # Get the text to encrypt and the key
            text_to_encrypt = request.POST.get('text_to_encrypt', '')
            key = request.POST.get('key', '')
            
            if text_to_encrypt and key:
                try:
                    encrypted_text = encrypt_3des(text_to_encrypt, key)
                    context['encrypted_text'] = encrypted_text
                    context['original_text'] = text_to_encrypt
                    context['key'] = key
                except Exception as e:
                    context['error'] = f"Encryption error: {str(e)}"
            
        elif action == 'decrypt':
            # Get the text to decrypt and the key
            text_to_decrypt = request.POST.get('text_to_decrypt', '')
            key = request.POST.get('key', '')
            
            if text_to_decrypt and key:
                try:
                    decrypted_text = decrypt_3des(text_to_decrypt, key)
                    context['decrypted_text'] = decrypted_text
                    context['encrypted_text'] = text_to_decrypt
                    context['key'] = key
                except Exception as e:
                    context['error'] = f"Decryption error: {str(e)}"
    
    return render(request, 'crypto_app/triple_des.html', context)

# View for RSA encryption/decryption
def rsa_encryption(request):
    context = {
        'encrypted_text': '',
        'decrypted_text': '',
        'private_key': '',
        'public_key': '',
        'original_text': '',
        'encryption_method': 'rsa'
    }
    
    if request.method == 'POST':
        action = request.POST.get('action', '')
        
        if action == 'generate_keys':
            # Generate new RSA keys
            private_key, public_key = generate_rsa_keys()
            context['private_key'] = private_key
            context['public_key'] = public_key
            
        elif action == 'encrypt':
            # Get the text to encrypt and the public key
            text_to_encrypt = request.POST.get('text_to_encrypt', '')
            public_key = request.POST.get('public_key', '')
            private_key = request.POST.get('private_key', '')  # Keep private key for later use
            
            if text_to_encrypt and public_key:
                try:
                    encrypted_text = encrypt_rsa(public_key, text_to_encrypt)
                    context['encrypted_text'] = encrypted_text
                    context['original_text'] = text_to_encrypt
                    context['public_key'] = public_key
                    context['private_key'] = private_key  # Preserve private key
                except Exception as e:
                    context['error'] = f"Encryption error: {str(e)}"
            
        elif action == 'decrypt':
            # Get the text to decrypt and the private key
            text_to_decrypt = request.POST.get('text_to_decrypt', '')
            private_key = request.POST.get('private_key', '')
            public_key = request.POST.get('public_key', '')  # Keep public key for later use
            
            if text_to_decrypt and private_key:
                try:
                    decrypted_text = decrypt_rsa(private_key, text_to_decrypt)
                    context['decrypted_text'] = decrypted_text
                    context['encrypted_text'] = text_to_decrypt
                    context['private_key'] = private_key
                    context['public_key'] = public_key  # Preserve public key
                except Exception as e:
                    context['error'] = f"Decryption error: {str(e)}"
    
    return render(request, 'crypto_app/rsa.html', context)

