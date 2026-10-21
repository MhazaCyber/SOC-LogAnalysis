# analyse_ip.py
# Compte les tentatives d'authentification par adresse IP source

import re
import csv
from collections import Counter

# Etape 1 : Lire le fichier de logs
with open("Linux_2k.log", "r", encoding="utf-8") as fichier:
    logs = fichier.readlines()

# Etape 2 : Preparer le compteur d'IP
compteur_ip = Counter()

# Etape 3 : Parcourir chaque ligne et extraire l'IP source
for ligne in logs:
    # On ne s'interesse qu'aux lignes d'echec suspectes
    if "authentication failure" in ligne or "Failed password" in ligne:
        # On cherche le motif rhost=<adresse IP>
        resultat = re.search(r"rhost=(\d+\.\d+\.\d+\.\d+)", ligne)
        if resultat:
            ip = resultat.group(1)
            compteur_ip[ip] += 1

# Etape 4 : Afficher le top 10 des IP les plus actives
print("=== Top 10 des IP sources les plus agressives ===")
for ip, nombre in compteur_ip.most_common(10):
    print(f"{ip} : {nombre} tentatives")

print(f"\nTotal d'IP distinctes detectees : {len(compteur_ip)}")

# Etape 5 : Exporter le classement complet en CSV
with open("ip_suspectes.csv", "w", newline="", encoding="utf-8") as fichier_csv:
    writer = csv.writer(fichier_csv)
    writer.writerow(["Adresse IP", "Nombre de tentatives"])
    for ip, nombre in compteur_ip.most_common():
        writer.writerow([ip, nombre])

print("\nClassement complet sauvegarde dans ip_suspectes.csv")