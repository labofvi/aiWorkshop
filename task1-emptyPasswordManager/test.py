import unittest
import json
import os
from main import (
    DEFAULT_SHIFT,
    add_password,
    caesar_decrypt,
    caesar_encrypt,
    generate_password,
    get_password,
    is_strong_password,
    load_passwords,
    save_passwords,
)

class TestPasswordManager(unittest.TestCase):

    def setUp(self):
        # Create a temporary vault.txt file for testing
        self.test_passwords_file = "test_vault.txt"
        self.test_passwords = [
            {"website": "example.com", "username": "user123", "password": "P@ssw0rd"},
            {"website": "test.com", "username": "testuser", "password": "TestP@ss123"}
        ]
        encrypted_entries = []
        for entry in self.test_passwords:
            encrypted_entries.append({
                "website": entry["website"],
                "username": entry["username"],
                "password": caesar_encrypt(entry["password"], DEFAULT_SHIFT),
            })
        with open(self.test_passwords_file, "w") as f:
            json.dump(encrypted_entries, f)
        load_passwords(self.test_passwords_file)

    def tearDown(self):
        # Remove the temporary vault.txt file after testing
        os.remove(self.test_passwords_file)

    def test_is_strong_password(self):
        # Test a strong password
        strong_password = "Str0ngP@ssw0rd"
        self.assertTrue(is_strong_password(strong_password))

        # Test a weak password (doesn't meet minimum length)
        weak_password = "Weak123"
        self.assertFalse(is_strong_password(weak_password))

        # Test a weak password (missing uppercase)
        weak_password = "weakpassword123!"
        self.assertFalse(is_strong_password(weak_password))

        # Test a weak password (missing special character)
        weak_password = "Weakpassword123"
        self.assertFalse(is_strong_password(weak_password))

    def test_generate_password(self):
        # Test generating a password of the specified length
        length = 12
        password = generate_password(length)
        self.assertEqual(len(password), length)
        self.assertTrue(is_strong_password(password))

        # Test generating a password of different length
        length = 16
        password = generate_password(length)
        self.assertEqual(len(password), length)
        self.assertTrue(is_strong_password(password))

    def test_add_password(self):
        # Test adding a password
        website = "example.net"
        username = "user456"
        password = "StrongP@ssw0rd"
        add_password(website, username, password)

        retrieved_username, retrieved_password = get_password(website)
        self.assertEqual(retrieved_username, username)
        self.assertEqual(retrieved_password, password)

    def test_get_password(self):
        # Test retrieving an existing password
        website = "example.com"
        username, password = get_password(website)
        self.assertEqual(username, "user123")
        self.assertEqual(password, "P@ssw0rd")

        # Test retrieving a non-existent password
        website = "nonexistent.com"
        username, password = get_password(website)
        self.assertIsNone(username)
        self.assertIsNone(password)

    def test_save_passwords(self):
        # Save passwords to a temporary file
        save_passwords(self.test_passwords, self.test_passwords_file)

        # Check if the saved passwords can be decrypted back to the original passwords
        with open(self.test_passwords_file, "r") as f:
            saved_passwords = json.load(f)

        decrypted_saved = []
        for entry in saved_passwords:
            decrypted_saved.append({
                "website": entry["website"],
                "username": entry["username"],
                "password": caesar_decrypt(entry["password"], DEFAULT_SHIFT),
            })

        self.assertEqual(decrypted_saved, self.test_passwords)

    def test_load_passwords(self):
        # Test loading passwords from an existing file
        loaded_passwords = load_passwords(self.test_passwords_file)
        self.assertEqual(loaded_passwords, self.test_passwords)

        # Test loading passwords from a non-existent file
        nonexistent_file = "nonexistent.txt"
        loaded_passwords = load_passwords(nonexistent_file)
        self.assertEqual(loaded_passwords, [])

if __name__ == '__main__':
    unittest.main()