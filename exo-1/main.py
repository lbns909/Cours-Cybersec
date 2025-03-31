import platform
import subprocess

#Demander l'adresse ip de l'utilisateur
ip = input("Entrer une ip address : ")

#Détecter l'OS pour adapter la commande
param = "-n" if platform.system().lower() == "windows" else "-c"

#construction du ping dans un list
command = ['ping', param, '1', ip]

print ("Ping en cours")

#On execute le ping
try:
    result = subprocess.run(command, stdout=subprocess.DEVNULL)
    if result.returncode == 0:
        print("La cible est en ligne")
    else:
        print("Aucune réponse")
except Exception as e:
    print("Erreur lors du ping {e} ")