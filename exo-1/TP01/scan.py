import socket
import threading


# Fonction pour récupérer la bannière du service
def grab_banner(host, port, results_file, open_ports, closed_ports):
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

                # Ajouter à la liste des ports ouverts
                open_ports.append((port, service, banner))

            else:
                open_ports.append((port, "Inconnu", "Aucune bannière reçue"))
        else:
            closed_ports.append(port)  # Ajouter à la liste des ports fermés
    except socket.timeout:
        closed_ports.append(port)  # Timeout -> Port fermé ou injoignable
    except Exception as e:
        closed_ports.append(port)  # Autres erreurs -> Port fermé ou injoignable
    finally:
        sock.close()  # S'assurer de fermer la connexion socket dans tous les cas


# Fonction pour regrouper les ports fermés en plages
def group_closed_ports(closed_ports):
    grouped_ports = []
    closed_ports.sort()  # Trier les ports fermés

    # Regrouper les ports fermés consécutifs
    start = None
    end = None
    for port in closed_ports:
        if start is None:
            start = port
            end = port
        elif port == end + 1:
            end = port
        else:
            if start == end:
                grouped_ports.append(f"{start} : fermé")
            else:
                grouped_ports.append(f"{start} à {end} : fermé")
            start = port
            end = port

    # Ajouter le dernier groupe
    if start is not None:
        if start == end:
            grouped_ports.append(f"{start} : fermé")
        else:
            grouped_ports.append(f"{start} à {end} : fermé")

    return grouped_ports


# Fonction pour scanner les ports dans la plage spécifiée
def scan_ports(host, start_port, end_port, results_file):
    open_ports = []  # Liste des ports ouverts avec services
    closed_ports = []  # Liste des ports fermés

    print(f"\n[***] Scan de {host} sur les ports de {start_port} à {end_port} [***]\n")
    threads = []

    # Lancer un thread pour chaque port
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=grab_banner, args=(host, port, results_file, open_ports, closed_ports))
        threads.append(t)
        t.start()

    # Attendre que tous les threads se terminent
    for t in threads:
        t.join()

    # Affichage des résultats
    print("\n[+] Ports ouverts :")
    if open_ports:
        for port, service, banner in open_ports:
            print(f"  Port {port} ouvert – Service détecté : {service} - {banner}")
            results_file.write(f"Port {port} ouvert – Service détecté : {service} - {banner}\n")
    else:
        print("  Aucun port ouvert détecté.")
        results_file.write("  Aucun port ouvert détecté.\n")

    print("\n[+] Ports fermés :")
    grouped_closed_ports = group_closed_ports(closed_ports)
    if grouped_closed_ports:
        for group in grouped_closed_ports:
            print(f"  {group}")
            results_file.write(f"  {group}\n")
    else:
        print("  Aucun port fermé détecté.")
        results_file.write("  Aucun port fermé détecté.\n")


# Programme principal
if __name__ == "__main__":
    # Demander à l'utilisateur l'adresse IP et la plage de ports
    target = input("Entrez l'adresse IP à scanner : ")
    start_port = int(input("Port de début : "))
    end_port = int(input("Port de fin : "))

    # Ouvrir automatiquement le fichier pour écrire les résultats
    with open("scan_results.txt", "w") as results_file:
        # Lancer le scan
        scan_ports(target, start_port, end_port, results_file)

    print("\nLes résultats ont été enregistrés dans 'scan_results.txt'.")
