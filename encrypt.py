from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import os


def encrypt(user_password, text_file, user_algorithm, user_hash, user_iteration_count):
    
    chosen_algorithm = "" # Name the algorithm
    length = 0  # Byte length for keys
    iv = os.urandom(16)  # Default Initialization vector
    chosen_hash = "SHA256"
    algorithm=hashes.SHA256() # Default Hash
    iterations = 0

    # User chose 512
    if user_hash == 2:
        algorithm=hashes.SHA512()
        chosen_hash = "SHA512"

    # 1 = 3DES
    if user_algorithm == 1:
        chosen_algorithm = "TriDES"
        length = 24
        iv = os.urandom(8)
        iterations = 475000
    # 2 = AES128
    elif user_algorithm == 2:
        chosen_algorithm = "AES128"
        length = 16
        iterations = 550000
    # 3 AES256
    else:
        chosen_algorithm = "AES256"
        length = 32
        iterations = 450000
    salt = os.urandom(16)
    
    if user_iteration_count != 0: iterations = user_iteration_count # Use user iteration count

    # Derive Master key
    kdf = PBKDF2HMAC(
    algorithm=algorithm,
    length=length,
    salt=salt,
    iterations=iterations,
    backend=default_backend()
    )
    # Master key from Password
    master_key = kdf.derive(user_password)

    # Derive Encryption key
    Ekdf = PBKDF2HMAC(
    algorithm=algorithm,
    length=length,
    salt= b"EncryptionSalt",
    iterations=1,
    backend=default_backend()
    )
    # Encryption key from Master key
    encryption_key= Ekdf.derive(master_key)

    # Derive HMAC key
    Hkdf = PBKDF2HMAC(
    algorithm=algorithm,
    length=length,
    salt= b"HMACSalt",
    iterations=1,
    backend=default_backend()
    )
    # HMAC key from Master key
    HMAC_key = Hkdf.derive(master_key)

    # Encryption
    
    # Padding for CBC
    with open(text_file, "rb") as file:
        plaintext = file.read()
    padder = PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Encrypt using CBC mode
    if (user_algorithm == 1): # cipher for 3DES
        cipher = Cipher(TripleDES(encryption_key), modes.CBC(iv), backend=default_backend())
    else:  # cipher for AES (length in key generation determines 128 or 256)
        cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # HMAC

    # Put IV and ciphertext together
    to_encrypt = iv + ciphertext
    # Create HMAC
    hmac = HMAC(HMAC_key, algorithm, backend=default_backend())
    # Generate HMAC cover over iv and ciphertext
    hmac.update(to_encrypt)
    # Save result
    hmac_tag = hmac.finalize()
    # Get text file name prefix
    output_prefix = text_file[:-4]
    # Save as binary file
    output_name = output_prefix + ".bin"
    with open(output_name, "wb") as file:
        # Metadata
        file.write(str(iterations).encode() + b"PBKDF#2" + chosen_algorithm.encode() + chosen_hash.encode() + salt)
        # HMAC
        file.write(hmac_tag)
        # IV and encrypted data
        file.write(to_encrypt)

    print("File has been encrypted into the following file: " + output_name)
        
        



