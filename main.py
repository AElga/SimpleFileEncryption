from encrypt import encrypt
from decrypt import decrypt

# User utility

print("Would you like to encrypt or decrypt? (Enter E for encrypt or D for decrypt):\n")
choice = str(input())
print()

# Encryption
if choice == "E":
    print("Enter your password:\n")
    user_password = str(input())
    print()

    print("Enter the name of the text file to encrypt (remember to include the .txt):\n")
    text_to_encrypt = str(input())
    print()

    print("Choose your encryption algorithm\nTripleDES (enter 1), AES128 (enter 2), AES256 (enter 3)\n")
    try:
        algorithm_used = int(input())
    # Ensure that the value is an integer
    except ValueError:
        print("Please enter 1, 2, or 3. Restart to program to try again")
        raise SystemExit
    # Ensure that the value is one of the valid values
    if algorithm_used < 1 or algorithm_used > 3:
        print("Please enter 1, 2, or 3. Restart to program to try again")
        raise SystemExit
    print()
    
    print("Choose your SHA hashing algorithm\n256 (enter 1) or 512 (enter 2)\n")
    try:
        hash_used = int(input())
    # Ensure that the value is an integer
    except ValueError:
        print("Please enter 1 or 2. Restart to program to try again")
        raise SystemExit
    # Ensure that the value is one of the valid values
    if hash_used < 1 or hash_used > 2:
        print("Please enter 1 or 2. Restart to program to try again")
        raise SystemExit
    print()
    
    print("Choose the number of iterations (enter a whole positive number, or enter 0 for defaults) \n")
    try:
        iteration_used = int(input())
    # Ensure that the value is an integer
    except ValueError:
        print("Error setting iteration (maybe the numer is less than 0 or not a whole number). Restart to program to try again")
        raise SystemExit
    print()
    # Ensure that the value is greater than or equal to 0
    if iteration_used >= 0:
        encrypt(user_password.encode(), text_to_encrypt, algorithm_used, hash_used, iteration_used)
        print()
    else:
        print("Error setting iteration (maybe the numer is less than 0 or not a whole number). Restart to program to try again")

# Decryption
elif choice == "D":
    print("Enter the name of the binary file to decrypt (remember to include the .bin):\n")
    text_to_decrypt = str(input())
    print()
    
    print("Enter your password:\n")
    user_password = str(input())
    print()
    
    decrypt(user_password.encode(), text_to_decrypt)
    print()

else:
    print("Please restart the program and enter either E or D")