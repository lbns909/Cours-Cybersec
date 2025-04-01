import socket
import threading


# Fonction pour récupérer la bannière du service
def grab_banner(host, port, results_file):
    try:
        # Créer un objet socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Timeout de 1 seconde

        # Connexion au port
        result = sock.connect_ex((host, port))
        if result == 0:
            banner = ""
            try:
                # Recevoir des données du service (jusqu'à 1024 octets)
                banner = sock.recv(1024).decode().strip()
            except Exception as e:
                banner = None  # Si la connexion échoue ou aucune donnée n'est reçue

            # Identification et affichage du service basé sur la bannière
            service = "Inconnu"
            if banner:
                if "SSH" in banner:
                    service = "SSH"
                elif "HTTP" in banner:
                    service = "HTTP"
                elif "Apache" in banner:
                    service = "Serveur Web Apache"
                elif "nginx" in banner:
                    service = "Serveur Web Nginx"

                # Affichage du port et du service détecté
                print(f"[+] Port {port} ouvert – Service détecté : {service} - {banner}")

                # Sauvegarder les résultats dans un fichier
                if results_file:
                    results_file.write(f"Port {port} ouvert – Service détecté : {service} - {banner}\n")
            else:
                print(f"Port {port} ouvert – Aucune bannière reçue.")
                if results_file:
                    results_file.write(f"Port {port} ouvert – Aucune bannière reçue.\n")

            # Envoi de requête HTTP si c'est un port 80 ou 443
            if port == 80 or port == 443:
                try:
                    request = "HEAD / HTTP/1.1\r\nHost: {}\r\n\r\n".format(host)
                    sock.sendall(request.encode())
                    response = sock.recv(1024).decode().strip()
                    print(f"    [*] Réponse HTTP : {response}")
                    if results_file:
                        results_file.write(f"    [*] Réponse HTTP : {response}\n")
                except Exception as e:
                    pass  # Si on ne reçoit pas de réponse HTTP, on ignore
        else:
            print(f"Port {port} fermé ou injoignable.")
    except socket.timeout:
        print(f"Timeout lors de la connexion au port {port}")
    except Exception as e:
        print(f"Erreur lors de la connexion au port {port}: {e}")
    finally:
        sock.close()  # S'assurer de fermer la connexion socket dans tous les cas


# Fonction pour scanner les ports dans la plage spécifiée
def scan_ports(host, start_port, end_port, results_file):
    print(f"\n[***] Scan de {host} sur les ports de {start_port} à {end_port} [***]\n")
    threads = []

    # Lancer un thread pour chaque port
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=grab_banner, args=(host, port, results_file))
        threads.append(t)
        t.start()

    # Attendre que tous les threads se terminent
    for t in threads:
        t.join()


# Programme principal
if __name__ == "__main__":
    # Demander à l'utilisateur l'adresse IP et la plage de ports
    target = input("Entrez l'adresse IP à scanner : ")
    start_port = int(input("Port de début : "))
    end_port = int(input("Port de fin : "))

    # Demander si l'utilisateur souhaite sauvegarder les résultats
    save_to_file = input("Voulez-vous sauvegarder les résultats dans un fichier (oui/non) ? ").lower()

    # Ouvrir le fichier si nécessaire
    results_file = None
    if save_to_file == "oui":
        results_file = open("scan_results.txt", "w")

    # Lancer le scan
    scan_ports(target, start_port, end_port, results_file)

    # Fermer le fichier après le scan si il a été ouvert
    if results_file:
        results_file.close()
