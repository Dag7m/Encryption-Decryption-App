from django.shortcuts import render
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

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

def index(request):
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
            
            if text_to_encrypt and public_key:
                try:
                    encrypted_text = encrypt_rsa(public_key, text_to_encrypt)
                    context['encrypted_text'] = encrypted_text
                    context['original_text'] = text_to_encrypt
                    context['public_key'] = public_key
                except Exception as e:
                    context['error'] = f"Encryption error: {str(e)}"
            
        elif action == 'decrypt':
            # Get the text to decrypt and the private key
            text_to_decrypt = request.POST.get('text_to_decrypt', '')
            private_key = request.POST.get('private_key', '')
            
            if text_to_decrypt and private_key:
                try:
                    decrypted_text = decrypt_rsa(private_key, text_to_decrypt)
                    context['decrypted_text'] = decrypted_text
                    context['encrypted_text'] = text_to_decrypt
                    context['private_key'] = private_key
                except Exception as e:
                    context['error'] = f"Decryption error: {str(e)}"
    
    return render(request, 'crypto_app/encryption.html', context)

