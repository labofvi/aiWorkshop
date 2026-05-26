import json
import re
import random
import string

# Caesar cipher encryption and decryption functions (pre-implemented)
def caesar_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
            encrypted_text += chr(shifted)
        else:
            encrypted_text += char
    return encrypted_text


def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)


# Password strength checker function (optional)
def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[^A-Za-z0-9]", password):
        return False
    return True


# Password generator function (optional)
def generate_password(length):
    if length < 8:
        length = 8

    specials = "!@#$%^&*()-_=+[]{};:,.<>?/"
    password_chars = [
        random.choice(string.ascii_lowercase),
        random.choice(string.ascii_uppercase),
        random.choice(string.digits),
        random.choice(specials),
    ]
    remaining_chars = random.choices(
        string.ascii_letters + string.digits + specials,
        k=length - len(password_chars),
    )
    password_chars.extend(remaining_chars)
    random.shuffle(password_chars)
    return "".join(password_chars)


# Initialize empty lists to store encrypted passwords, websites, and usernames
encrypted_passwords = []
websites = []
usernames = []
DEFAULT_SHIFT = 3


# Function to add a new password
def add_password(website=None, username=None, password=None, password_list=None):
    """
    Add a new password to the password manager.

    This function can be used interactively or with direct arguments.
    """
    if website is None:
        website = input("Enter website: ").strip()
    if username is None:
        username = input("Enter username: ").strip()

    if password is None:
        while True:
            option = input("Enter 'g' to generate a password or 'm' to enter one manually: ").strip().lower()
            if option == "g":
                length_input = input("Password length (minimum 8): ").strip()
                try:
                    length = max(8, int(length_input))
                except ValueError:
                    length = 12
                password = generate_password(length)
                print(f"Generated password: {password}")
                break
            elif option == "m":
                password = input("Enter password: ")
                if not is_strong_password(password):
                    print("Warning: This password is weak. A strong password has at least 8 characters, including uppercase, lowercase, digits, and special characters.")
                    confirm = input("Use this password anyway? (y/n): ").strip().lower()
                    if confirm == "y":
                        break
                    continue
                break
            else:
                print("Invalid option. Please enter 'g' or 'm'.")

    encrypted = caesar_encrypt(password, DEFAULT_SHIFT)
    websites.append(website)
    usernames.append(username)
    encrypted_passwords.append(encrypted)

    if password_list is not None:
        password_list.append({"website": website, "username": username, "password": password})

    print("Password added successfully.")
    return website, username, password


# Function to retrieve a password
def get_password(website=None):
    """
    Retrieve a password for a given website.

    This function can be called interactively or with a website argument.
    """
    if website is None:
        website = input("Enter website: ").strip()

    for index, stored_website in enumerate(websites):
        if stored_website.lower() == website.lower():
            decrypted = caesar_decrypt(encrypted_passwords[index], DEFAULT_SHIFT)
            username = usernames[index]
            print(f"Website: {stored_website}")
            print(f"Username: {username}")
            print(f"Password: {decrypted}")
            return username, decrypted

    print("No password found for that website.")
    return None, None


# Function to save passwords to a JSON file
def save_passwords(passwords=None, file_name="vault.txt"):
    """
    Save the password vault to a file.

    This function writes encrypted passwords to the file using the provided
    Caesar cipher function. The file stores the password field in encrypted
    form so passwords are not written as plain text.
    """
    if passwords is None:
        passwords = []
        for website, username, encrypted_password in zip(websites, usernames, encrypted_passwords):
            passwords.append({"website": website, "username": username, "password": encrypted_password})
    else:
        encrypted_entries = []
        for entry in passwords:
            website = entry.get("website", "")
            username = entry.get("username", "")
            password = entry.get("password", "")
            encrypted_entries.append({
                "website": website,
                "username": username,
                "password": caesar_encrypt(password, DEFAULT_SHIFT),
            })
        passwords = encrypted_entries

    with open(file_name, "w") as file:
        json.dump(passwords, file, indent=4)

    print(f"Passwords saved to {file_name}.")
    return passwords


# Function to load passwords from a JSON file
def load_passwords(file_name="vault.txt"):
    """
    Load passwords from a file into the password vault.

    The file is expected to contain encrypted passwords. This function loads
    the encrypted values internally and returns a decrypted copy of the data.
    """
    try:
        with open(file_name, "r") as file:
            loaded_passwords = json.load(file)
    except FileNotFoundError:
        print(f"File not found: {file_name}")
        return []
    except json.JSONDecodeError:
        print(f"Invalid JSON in file: {file_name}")
        return []

    websites.clear()
    usernames.clear()
    encrypted_passwords.clear()

    decrypted_entries = []
    for entry in loaded_passwords:
        website = entry.get("website", "")
        username = entry.get("username", "")
        encrypted_password = entry.get("password", "")
        websites.append(website)
        usernames.append(username)
        encrypted_passwords.append(encrypted_password)
        decrypted_entries.append({
            "website": website,
            "username": username,
            "password": caesar_decrypt(encrypted_password, DEFAULT_SHIFT),
        })

    return decrypted_entries


# Main method
def main():
    while True:
        print("\nPassword Manager Menu:")
        print("1. Add Password")
        print("2. Get Password")
        print("3. Save Passwords")
        print("4. Load Passwords")
        print("5. Quit")

        choice = input("Enter your choice: ")

        if choice == "1":
            add_password()
        elif choice == "2":
            get_password()
        elif choice == "3":
            save_passwords()
        elif choice == "4":
            load_passwords()
            print("Passwords loaded successfully!")
        elif choice == "5":
            break
        else:
            print("Invalid choice. Please try again.")


# Execute the main function when the program is run
if __name__ == "__main__":
    main()
