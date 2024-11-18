import logging
import json
import base64
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, CallbackContext
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from os import urandom

# Set up logging to monitor errors and important events
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=logging.INFO)
logger = logging.getLogger(__name__)

# Define the encryption and decryption methods
def derive_key(password: str) -> bytes:
    """Derive a key using PBKDF2 with HMAC (SHA-256) from the password."""
    salt = urandom(16)  # Salt for PBKDF2
    kdf = PBKDF2HMAC(algorithm=hashlib.sha256(), salt=salt, length=32, iterations=100000, backend=default_backend())
    return kdf.derive(password.encode())

def encrypt_seed(seed_phrase: str, password: str) -> str:
    """Encrypt the seed phrase using AES encryption."""
    key = derive_key(password)
    iv = urandom(16)  # Initialization Vector (IV) for AES encryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(seed_phrase.encode()) + padder.finalize()
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_data).decode()  # Return base64 encoded encrypted string

def decrypt_seed(encrypted_seed: str, password: str) -> str:
    """Decrypt the seed phrase using AES decryption."""
    data = base64.b64decode(encrypted_seed)
    iv = data[:16]
    encrypted_data = data[16:]
    key = derive_key(password)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data.decode()

# Store and retrieve seeds from a JSON file
def load_seeds():
    """Load the encrypted seed phrases from a JSON file."""
    try:
        with open("seeds.json", "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

def save_seeds(seeds):
    """Save the encrypted seed phrases to a JSON file."""
    with open("seeds.json", "w") as file:
        json.dump(seeds, file)

# Command handlers for the bot
async def start(update: Update, context: CallbackContext) -> None:
    """Send a welcome message when the /start command is issued."""
    await update.message.reply_text('Welcome! Use /addseed to store a wallet seed.')

async def add_seed(update: Update, context: CallbackContext) -> None:
    """Prompt the user to send a wallet seed phrase."""
    await update.message.reply_text('Please send your wallet seed phrase.')

async def store_seed(update: Update, context: CallbackContext) -> None:
    """Store the seed phrase securely."""
    seed_phrase = update.message.text
    if not seed_phrase:
        await update.message.reply_text('Seed phrase cannot be empty.')
        return

    # Ask for the master password to encrypt the seed
    await update.message.reply_text('Please enter your master password to secure the seed.')

    context.user_data['seed_phrase'] = seed_phrase

async def process_master_password(update: Update, context: CallbackContext) -> None:
    """Process the master password for encryption."""
    master_password = update.message.text
    seed_phrase = context.user_data.get('seed_phrase')

    if not master_password or not seed_phrase:
        await update.message.reply_text('No seed phrase or password provided.')
        return

    encrypted_seed = encrypt_seed(seed_phrase, master_password)
    seeds = load_seeds()

    # Save encrypted seed with a unique key (e.g., user ID or a custom name)
    seeds[update.message.from_user.id] = encrypted_seed
    save_seeds(seeds)

    await update.message.reply_text('Your wallet seed has been securely stored.')

async def retrieve_seed(update: Update, context: CallbackContext) -> None:
    """Retrieve a stored wallet seed."""
    # Ask for the master password to decrypt the seed
    await update.message.reply_text('Please enter your master password to retrieve your wallet seed.')

async def process_retrieve_password(update: Update, context: CallbackContext) -> None:
    """Process the master password for decryption."""
    master_password = update.message.text
    seeds = load_seeds()

    # Retrieve the user's encrypted seed
    encrypted_seed = seeds.get(update.message.from_user.id)

    if not encrypted_seed:
        await update.message.reply_text('No seed found for this user.')
        return

    decrypted_seed = decrypt_seed(encrypted_seed, master_password)
    await update.message.reply_text(f'Your wallet seed is: {decrypted_seed}')

# Error handler
def error(update: Update, context: CallbackContext) -> None:
    """Log errors."""
    logger.warning(f'Update {update} caused error {context.error}')

# Main function to run the bot
async def main() -> None:
    """Start the bot and set up handlers."""
    TOKEN = '8172496913:AAGqJZB1yCDRIsAqeDX2q_niLcwMlIfFPsU'  # Replace with your actual token
    
    application = Application.builder().token(TOKEN).build()

    # Add command handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("addseed", add_seed))
    application.add_handler(CommandHandler("retrieveseed", retrieve_seed))

    # Add message handlers for user input
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, store_seed))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, process_master_password))

    # Start the bot with polling
    await application.run_polling()

# Entry point for the script
if __name__ == '__main__':
    import asyncio
    asyncio.run(main())
