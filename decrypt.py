from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend

# Read data from files
def decrypt(user_password, file_to_decrypt):
    # Open file and get contents
    with open(file_to_decrypt, "rb") as file:
        contents = file.read()

    # Parse iteration number
    iteration_count = 0
    for byte in contents:
        # If the curent byte equals 'P'
        if byte == 80:
            break   # Stop
        iteration_count += 1

    # Parameters
    hmac_size = 32  # default HMAC size for SHA256
    iv_size = 16    # default iv size for AES
    # Get metadata
    iterations = int(contents[:iteration_count].decode())
    meta_algorithm = contents[iteration_count + 7:iteration_count + 13].decode() # Name the algorithm
    meta_hash = contents[iteration_count + 13:iteration_count + 19].decode()
    salt = contents[iteration_count + 19:iteration_count + 35]

    algorithm=hashes.SHA256() # Default Hash
    
    if meta_hash == "SHA512":
        algorithm=hashes.SHA512()
        hmac_size = 64
    # Meta data has been tampered with or saved incorrectly
    elif meta_hash != "SHA256":
        print("HMAC verification failed! The data may have been tampered with or the incorrect password may have been used.")
        exit()

    length = 0  # Byte length for keys

    # 1 = 3DES
    if meta_algorithm == "TriDES":
        length = 24
        iv_size = 8
    # 2 = AES128
    elif meta_algorithm == "AES128":
        length = 16
    # 3 AES256
    elif meta_algorithm == "AES256":
        length = 32
    else:  # Meta data has been tampered with or saved incorrectly
        print("HMAC verification failed! The data may have been tampered with or the incorrect password may have been used.")
        exit()
    # Get HMAC signature
    hmac_tag = contents[iteration_count + 35:iteration_count + 35 + hmac_size]
    # Get rest of data
    iv_and_ciphertext =  contents[iteration_count + 35 + hmac_size:]
    
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
    decryption_key = Ekdf.derive(master_key)

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

    # Verify the HMAC
    hmac = HMAC(HMAC_key, algorithm, backend=default_backend())
    hmac.update(iv_and_ciphertext)

    try:
        hmac.verify(hmac_tag)  # Verify the HMAC tag
        print("HMAC verification succeeded.")
    except Exception:
        print("HMAC verification failed! The data may have been tampered with or the incorrect password may have been used.")
        exit()

    # Split the IV and ciphertext
    iv = iv_and_ciphertext[:iv_size]  # Based on 3DES or AES
    ciphertext = iv_and_ciphertext[iv_size:]  # Rest is the ciphertext
    
    #Decryption
    if (meta_algorithm == "TriDES"): # cipher for 3DES
        cipher = Cipher(TripleDES(decryption_key), modes.CBC(iv), backend=default_backend())
    else:  # cipher for AES (length in key generation determines 128 or 256)
        cipher = Cipher(algorithms.AES(decryption_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    # Output the plaintext
    output = "decrypted_" + file_to_decrypt[:-4] + ".txt"
    with open(output, "wt") as file:
        file.write(plaintext.decode())
    