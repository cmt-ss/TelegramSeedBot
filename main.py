import logging
from telegram import Update
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, CallbackContext
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os
import json

# Replace with your Telegram Bot Token
TOKEN = '8172496913:AAGqJZB1yCDRIsAqeDX2q_niLcwMlIfFPsU'

# Initialize logging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=logging.INFO)
logger = logging.getLogger(__name__)

# Global Variables
SALT = b"1234567890abcdef"  # Example Salt
SEEDS_STORAGE = "seeds.json"
key = None


# Function to derive the key using PBKDF2 from the master password
def derive_key(password: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


# Function to encrypt the seed using AES
def encrypt_seed(seed: str, key: bytes) -> str:
    iv = os.urandom(16)  # Generate a random IV for each encryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_seed = seed + (16 - len(seed) % 16) * " "  # Padding to ensure multiple of 16
    encrypted_seed = encryptor.update(padded_seed.encode()) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_seed).decode()


# Function to decrypt the seed using AES
def decrypt_seed(encrypted_seed: str, key: bytes) -> str:
    data = base64.b64decode(encrypted_seed)
    iv = data[:16]
    encrypted_data = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data.decode().rstrip()  # Remove padding


# Command handler for the /start command
def start(update: Update, context: CallbackContext) -> None:
    update.message.reply_text('Welcome to Seed Manager bot! Please enter your master password to begin.')


# Command handler for setting the master password
def set_master_password(update: Update, context: CallbackContext) -> None:
    global key
    if len(context.args) == 0:
        update.message.reply_text('Please provide a master password with the command: /setpassword <your_password>')
        return

    password = context.args[0]
    key = derive_key(password)
    update.message.reply_text('Master password set. You can now add and view seed phrases using the /addseed and /viewseeds commands.')


# Command handler for adding a seed phrase
def add_seed(update: Update, context: CallbackContext) -> None:
    if key is None:
        update.message.reply_text('Please set your master password first using /setpassword <your_password>')
        return

    if len(context.args) < 2:
        update.message.reply_text('Please provide both label and seed phrase in the format: /addseed <label> <seed_phrase>')
        return

    label = context.args[0]
    seed_phrase = " ".join(context.args[1:])
    
    # Encrypt the seed
    encrypted_seed = encrypt_seed(seed_phrase, key)

    # Save the seed to file (JSON format)
    seeds = {}
    if os.path.exists(SEEDS_STORAGE):
        with open(SEEDS_STORAGE, 'r') as f:
            seeds = json.load(f)

    seeds[label] = encrypted_seed

    with open(SEEDS_STORAGE, 'w') as f:
        json.dump(seeds, f)

    update.message.reply_text(f"Seed for {label} saved successfully.")


# Command handler for viewing saved seeds
def view_seeds(update: Update, context: CallbackContext) -> None:
    if key is None:
        update.message.reply_text('Please set your master password first using /setpassword <your_password>')
        return

    if not os.path.exists(SEEDS_STORAGE):
        update.message.reply_text('No seeds found. Please add seeds using /addseed command.')
        return

    with open(SEEDS_STORAGE, 'r') as f:
        seeds = json.load(f)

    if len(seeds) == 0:
        update.message.reply_text('No seeds found.')
        return

    message = "Your saved seeds:\n\n"
    for label, encrypted_seed in seeds.items():
        decrypted_seed = decrypt_seed(encrypted_seed, key)
        message += f"{label}: {decrypted_seed}\n"

    update.message.reply_text(message)


# Command handler for deleting a seed
def delete_seed(update: Update, context: CallbackContext) -> None:
    if key is None:
        update.message.reply_text('Please set your master password first using /setpassword <your_password>')
        return

    if len(context.args) == 0:
        update.message.reply_text('Please provide the label of the seed to delete using /deleteseed <label>')
        return

    label = context.args[0]

    if not os.path.exists(SEEDS_STORAGE):
        update.message.reply_text('No seeds found to delete.')
        return

    with open(SEEDS_STORAGE, 'r') as f:
        seeds = json.load(f)

    if label not in seeds:
        update.message.reply_text(f"Seed with label '{label}' not found.")
        return

    del seeds[label]

    with open(SEEDS_STORAGE, 'w') as f:
        json.dump(seeds, f)

    update.message.reply_text(f"Seed with label '{label}' has been deleted.")


# Error handler
def error(update: Update, context: CallbackContext) -> None:
    logger.warning(f'Update {update} caused error {context.error}')


# Main function to run the bot
def main() -> None:
    updater = Updater(TOKEN)

    dp = updater.dispatcher

    # Register command handlers
    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(CommandHandler("setpassword", set_master_password))
    dp.add_handler(CommandHandler("addseed", add_seed))
    dp.add_handler(CommandHandler("viewseeds", view_seeds))
    dp.add_handler(CommandHandler("deleteseed", delete_seed))

    # Log all errors
    dp.add_error_handler(error)

    # Start the bot
    updater.start_polling()

    updater.idle()


if __name__ == '__main__':
    main()
