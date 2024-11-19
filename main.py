import time
import json
import telebot
from cryptography.fernet import Fernet

# Initialize bot with your token
TOKEN = '8172496913:AAGqJZB1yCDRIsAqeDX2q_niLcwMlIfFPsU'
bot = telebot.TeleBot(TOKEN)

# Generate a secure encryption key if not available
def get_encryption_key():
    try:
        with open('encryption.key', 'r') as key_file:
            return key_file.read().encode()
    except FileNotFoundError:
        key = Fernet.generate_key()
        with open('encryption.key', 'w') as key_file:
            key_file.write(key.decode())
        return key

ENCRYPTION_KEY = get_encryption_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

# Load user data
def load_data():
    try:
        with open('users.json', 'r') as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"users": {}}

# Save user data
def save_data(data):
    with open('users.json', 'w') as file:
        json.dump(data, file)

# Display main menu
def menu(user_id):
    keyboard = telebot.types.ReplyKeyboardMarkup(True)
    keyboard.row('🔑 Add Seed Phrase', '📜 View Seed Phrases')
    keyboard.row('🔒 Secure with Master Password', '⚙️ Settings')
    bot.send_message(user_id, "*Main Menu*", parse_mode="Markdown", reply_markup=keyboard)

# Start command handler
@bot.message_handler(commands=['start'])
def start(message):
    user_id = str(message.chat.id)
    data = load_data()

    if user_id not in data["users"]:
        data["users"][user_id] = {"seed_phrases": {}, "master_password": None}
        save_data(data)

    bot.send_message(user_id, "*Welcome to the Seed Phrase Wallet Bot!*", parse_mode="Markdown")
    menu(user_id)

# Add seed phrase
@bot.message_handler(func=lambda msg: msg.text == '🔑 Add Seed Phrase')
def add_seed_phrase_prompt(message):
    user_id = str(message.chat.id)
    send = bot.send_message(user_id, "_Enter the name of the wallet (e.g., Bitcoin, Ethereum)._", parse_mode="Markdown")
    bot.register_next_step_handler(send, add_seed_phrase)

def add_seed_phrase(message):
    user_id = str(message.chat.id)
    wallet_name = message.text
    send = bot.send_message(user_id, "_Enter the seed phrase for this wallet._", parse_mode="Markdown")
    bot.register_next_step_handler(send, save_seed_phrase, wallet_name)

def save_seed_phrase(message, wallet_name):
    user_id = str(message.chat.id)
    seed_phrase = message.text
    data = load_data()

    encrypted_phrase = cipher_suite.encrypt(seed_phrase.encode()).decode()
    data["users"][user_id]["seed_phrases"][wallet_name] = encrypted_phrase
    save_data(data)

    bot.send_message(user_id, "✅ Seed phrase saved successfully!")
    menu(user_id)

# View seed phrases
@bot.message_handler(func=lambda msg: msg.text == '📜 View Seed Phrases')
def view_seed_phrases(message):
    user_id = str(message.chat.id)
    data = load_data()

    seed_phrases = data["users"][user_id]["seed_phrases"]
    if not seed_phrases:
        bot.send_message(user_id, "❌ No seed phrases found.")
    else:
        msg = "*Your Seed Phrases:*\n"
        for wallet, encrypted_phrase in seed_phrases.items():
            decrypted_phrase = cipher_suite.decrypt(encrypted_phrase.encode()).decode()
            msg += f"• {wallet}: `{decrypted_phrase}`\n"
        bot.send_message(user_id, msg, parse_mode="Markdown")
    menu(user_id)

# Secure with master password
@bot.message_handler(func=lambda msg: msg.text == '🔒 Secure with Master Password')
def set_master_password_prompt(message):
    user_id = str(message.chat.id)
    send = bot.send_message(user_id, "_Enter a master password to secure your wallet._", parse_mode="Markdown")
    bot.register_next_step_handler(send, save_master_password)

def save_master_password(message):
    user_id = str(message.chat.id)
    master_password = message.text
    data = load_data()

    encrypted_password = cipher_suite.encrypt(master_password.encode()).decode()
    data["users"][user_id]["master_password"] = encrypted_password
    save_data(data)

    bot.send_message(user_id, "✅ Master password set successfully!")
    menu(user_id)

# Settings
@bot.message_handler(func=lambda msg: msg.text == '⚙️ Settings')
def settings(message):
    user_id = str(message.chat.id)
    keyboard = telebot.types.ReplyKeyboardMarkup(True)
    keyboard.row('🔄 Change Master Password', '❌ Delete All Data')
    keyboard.row('🔙 Back to Menu')
    bot.send_message(user_id, "*Settings Menu*", parse_mode="Markdown", reply_markup=keyboard)

# Change master password
@bot.message_handler(func=lambda msg: msg.text == '🔄 Change Master Password')
def change_master_password_prompt(message):
    user_id = str(message.chat.id)
    send = bot.send_message(user_id, "_Enter your new master password._", parse_mode="Markdown")
    bot.register_next_step_handler(send, save_master_password)

# Delete all data
@bot.message_handler(func=lambda msg: msg.text == '❌ Delete All Data')
def delete_all_data(message):
    user_id = str(message.chat.id)
    data = load_data()

    data["users"].pop(user_id, None)
    save_data(data)

    bot.send_message(user_id, "✅ All your data has been deleted.")
    menu(user_id)

# Handle unrecognized commands
@bot.message_handler(func=lambda message: True)
def unknown_command(message):
    bot.send_message(message.chat.id, "❌ Command not recognized. Use the menu options.")
    menu(message.chat.id)

# Run the bot
bot.polling()
