import os
import hmac
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Since encryption.py is in routes/ folder, import config from parent directory
from website.config import Config

class DataEncryption:
    """
    Handles encryption and decryption of sensitive personal data
    """
    
    def __init__(self, password=None):
        """
        Initialize encryption with a password from config
        """
        if password is None:
            # 🔧 Get encryption key from your config file
            password = Config.ENCRYPTION_KEY.encode()
        elif isinstance(password, str):
            password = password.encode()
            
        self.password = password
        self.cipher_suite = self._create_cipher_suite()
    
    def _create_cipher_suite(self):
        """
        Create Fernet cipher suite from password
        """
        # 🔧 CHANGE: Get salt from config instead of hardcoded value
        salt = Config.ENCRYPTION_SALT.encode()
        
        # Derive key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.password))
        return Fernet(key)
    
    def encrypt_data(self, data):
        """
        Encrypt a string and return bytes
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        return self.cipher_suite.encrypt(data)
    
    def decrypt_data(self, encrypted_data):
        """
        Decrypt bytes and return string
        """
        if isinstance(encrypted_data, str):
            encrypted_data = encrypted_data.encode('utf-8')
        decrypted_bytes = self.cipher_suite.decrypt(encrypted_data)
        return decrypted_bytes.decode('utf-8')
    
    def generate_hmac(self, *data_fields):
        """
        Generate HMAC for data integrity verification
        Combines multiple fields and creates a hash
        """
        # Combine all data fields
        combined_data = '|'.join(str(field) for field in data_fields if field)
        
        # Generate HMAC
        hmac_obj = hmac.new(
            self.password,
            combined_data.encode('utf-8'),
            hashlib.sha256
        )
        return hmac_obj.digest()
    
    def verify_hmac(self, stored_hmac, *data_fields):
        """
        Verify HMAC to check data integrity
        """
        expected_hmac = self.generate_hmac(*data_fields)
        return hmac.compare_digest(stored_hmac, expected_hmac)

# Convenience functions for easy use
def encrypt_personal_data(nric, email, address):
    """
    Encrypt personal data and return encrypted values + HMAC
    """
    encryptor = DataEncryption()
    
    encrypted_nric = encryptor.encrypt_data(nric) if nric else b''
    encrypted_email = encryptor.encrypt_data(email) if email else b''
    encrypted_address = encryptor.encrypt_data(address) if address else b''
    
    # Generate HMAC for integrity
    data_hmac = encryptor.generate_hmac(nric, email, address)
    
    return encrypted_nric, encrypted_email, encrypted_address, data_hmac

def decrypt_personal_data(encrypted_nric, encrypted_email, encrypted_address, stored_hmac=None):
    """
    Decrypt personal data and verify integrity
    """
    encryptor = DataEncryption()
    
    try:
        nric = encryptor.decrypt_data(encrypted_nric) if encrypted_nric else ''
        email = encryptor.decrypt_data(encrypted_email) if encrypted_email else ''
        address = encryptor.decrypt_data(encrypted_address) if encrypted_address else ''
        
        # Verify HMAC if provided
        if stored_hmac:
            if not encryptor.verify_hmac(stored_hmac, nric, email, address):
                raise ValueError("Data integrity check failed - data may be corrupted")
        
        return nric, email, address
    
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

# Test function
def test_encryption():
    """
    Test the encryption/decryption functionality
    """
    print("🔐 Testing encryption...")
    
    # 🔧 Show configuration being used
    print(f"📋 Using encryption key from config: {Config.ENCRYPTION_KEY[:10]}...")
    print(f"🧂 Using encryption salt from config: {Config.ENCRYPTION_SALT[:10]}...")
    
    # Test data
    test_nric = "123456-78-9012"
    test_email = "student@example.com"
    test_address = "123 University Street, KL, Malaysia"
    
    # Encrypt
    enc_nric, enc_email, enc_address, hmac_val = encrypt_personal_data(
        test_nric, test_email, test_address
    )
    
    print(f"✅ Encrypted NRIC: {enc_nric[:20]}...")
    print(f"✅ Encrypted Email: {enc_email[:20]}...")
    print(f"✅ Encrypted Address: {enc_address[:20]}...")
    print(f"✅ HMAC: {hmac_val[:10]}...")
    
    # Decrypt
    dec_nric, dec_email, dec_address = decrypt_personal_data(
        enc_nric, enc_email, enc_address, hmac_val
    )
    
    print(f"✅ Decrypted NRIC: {dec_nric}")
    print(f"✅ Decrypted Email: {dec_email}")
    print(f"✅ Decrypted Address: {dec_address}")
    
    # Verify
    assert dec_nric == test_nric
    assert dec_email == test_email
    assert dec_address == test_address
    
    print("🎉 Encryption test passed!")

if __name__ == "__main__":
    test_encryption()