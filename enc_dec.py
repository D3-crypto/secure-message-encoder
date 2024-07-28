import base64
import random
import string
import hashlib
import json
from cryptography.fernet import Fernet, InvalidToken

# File to store the encryption key
KEY_FILE = "secret.key"
# File to store encoded messages and their hash values
STORAGE_FILE = "encoded_messages.json"

def generate_key():
    """Generate and save a key for encryption and decryption."""
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(key)
    return key

def load_key():
    """Load the previously generated key."""
    try:
        with open(KEY_FILE, 'rb') as key_file:
            return key_file.read()
    except FileNotFoundError:
        return generate_key()

# Load the encryption key
key = load_key()
cipher_suite = Fernet(key)

def random_chars_generator(length=5):
    """Generate a string of random characters of a given length."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def encoding_words(word):
    """Encode a single word."""
    if len(word) >= 3:
        new_word = word[1:] + word[0]
        random_prefix = random_chars_generator()
        random_suffix = random_chars_generator()
        return random_prefix + new_word + random_suffix
    else:
        return word[::-1]
    
def decoding_words(word):
    """Decode a single word."""
    if len(word) < 3:
        return word[::-1]
    else:
        new_word = word[5:-5]  # Remove the prefix and suffix of known length (5 characters each)
        return new_word[-1] + new_word[:-1]

def msg_encoding(msg):
    """Encode a message."""
    words = msg.split()
    encoded_words = [encoding_words(word) for word in words]
    return ' '.join(encoded_words)

def msg_decoding(msg):
    """Decode a message."""
    words = msg.split()
    decoded_words = [decoding_words(word) for word in words]
    return ' '.join(decoded_words)

def msg_hash(msg):
    """Hash a message using SHA-256 and encode it with base64."""
    sha256_hash = hashlib.sha256(msg.encode()).digest()
    return base64.b64encode(sha256_hash).decode()

def verify_hash(msg, hash_val):
    """Verify the hash of a message."""
    return msg_hash(msg) == hash_val

def load_encoded_messages():
    """Load encoded messages from the encrypted storage file."""
    try:
        with open(STORAGE_FILE, 'rb') as file:
            encrypted_data = file.read()
            if not encrypted_data:
                return {}
            decrypted_data = cipher_suite.decrypt(encrypted_data)
            return json.loads(decrypted_data)
    except FileNotFoundError:
        return {}
    except (json.JSONDecodeError, ValueError, InvalidToken):
        return {}

def save_encoded_message(encoded_message, hashed_message):
    """Save an encoded message and its hash value to the encrypted storage file."""
    encoded_messages = load_encoded_messages()
    encoded_messages[encoded_message] = hashed_message
    encrypted_data = cipher_suite.encrypt(json.dumps(encoded_messages).encode())
    with open(STORAGE_FILE, 'wb') as file:
        file.write(encrypted_data)

def handle_user_choice():
    """Handle the user options."""
    while True:
        choice = input("Do you want to decrypt a message, encode another message, or exit? (Enter 'decrypt', 'encode', or 'exit'): ").strip().lower()
        if choice == 'exit':
            print("Thank you\nExiting")
            break
        elif choice == 'decrypt':
            hashed_message = input("Enter the hash key for decryption: ").strip()
            encoded_messages = load_encoded_messages()
            for encoded_message, hash_val in encoded_messages.items():
                if hash_val == hashed_message:
                    decoded_message = msg_decoding(encoded_message)
                    print("Decoded Message:", decoded_message)
                    return
            print("Hash verification failed. The hash key may be incorrect or the message may have been tampered with.")
        elif choice == 'encode':
            main()
            break
        else:
            print("Invalid choice. Please enter 'decrypt', 'encode', or 'exit'.")

def main():
    action = input("Do you want to encode or decode? (enter 'code' or 'decode'): ").strip().lower()
    if action not in {'code', 'decode'}:
        print("Invalid action. Please enter 'code' or 'decode'.")
        return
    
    if action == 'code':
        msg = input("Enter the message to encode: ").strip()
        encoded_message = msg_encoding(msg)
        hashed_message = msg_hash(encoded_message)
        save_encoded_message(encoded_message, hashed_message)
        print("Hashed Message:", hashed_message)
        handle_user_choice()
    else:
        handle_user_choice()

if __name__ == "__main__":
    main()
