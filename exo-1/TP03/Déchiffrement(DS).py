def decrypt_file(filepath, fernet):
    try:
        with open(filepath, "rb") as file:
            encrypted_data = file.read()

        decrypted_data = fernet.decrypt(encrypted_data)

        with open(filepath, "wb") as file:
            file.write(decrypted_data)

        return True
    except Exception as e:
        print(f"Échec déchiffrement {filepath}: {str(e)}")
        return False