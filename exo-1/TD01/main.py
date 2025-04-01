# Scanner de ports
import threading
import socket
from threading import Thread


# Definir une fonction qui va tester un port specifique

def scan_port(host, port):
    # creation d'un objet socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #Definir un délais pour éviter le TIMEOUT et blocage
        sock.settimeout(1)
        #Tentative de connexion sur le port (0 si la connexion a réussi)
        result = sock.connect_ex((host, port))
        #si le port est ouvert (result = 0) on l'affiche
        if result == 0:
            print("Port " + str(port) + " est ouvert")
            #on ferme le socket
            sock.close()
    except Exception as e:
    #Gestion des erreurs
        print(f"[-] Erreur sur le port {port}: {e}")
# On demande l'ip de la cible
target = input("Entrer une ip address : ")

# On demande la plage d'adresse à scanner
start_port = int(input("Port de debut : "))
end_port = int(input("Port de fin : "))
#on informe l'utilisateur que le scan débute
print(f"\n[***] scan {target} sur les ports {start_port} à {end_port} [***]\n")
for port in range(start_port, end_port +1):
        #on crée un thread (execution parallèle pour chaque port
    t = threading.Thread(target=scan_port, args=(target, port))
    t.start()