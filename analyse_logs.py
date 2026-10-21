# analyse_logs.py
# Script d'analyse automatique de logs Linux

# Etape 1 : Lire le fichier de logs
with open("Linux_2k.log", "r", encoding="utf-8") as fichier:
    logs = fichier.readlines()

# Etape 2 : Selectionner les lignes 200 a 500
sous_ensemble = logs[199:500]

# Etape 3 : Preparer la liste et les compteurs
entrees_suspectes = []
compteur_echec_connexion = 0
compteur_echec_auth = 0
compteur_utilisateur_inconnu = 0

# Etape 4 : Detecter les patterns suspects
for ligne in sous_ensemble:
    if "Failed password" in ligne:
        entrees_suspectes.append(("Echec connexion", ligne.strip()))
        compteur_echec_connexion += 1
    elif "authentication failure" in ligne:
        entrees_suspectes.append(("Echec authentification", ligne.strip()))
        compteur_echec_auth += 1
    elif "user unknown" in ligne or "invalid user" in ligne:
        entrees_suspectes.append(("Utilisateur inconnu", ligne.strip()))
        compteur_utilisateur_inconnu += 1

# Etape 5 : Afficher les resultats avec un resume
print("=== Entrees suspectes (lignes 200-500) ===")
for type_evt, entree in entrees_suspectes:
    print(f"[{type_evt}] {entree}")

print(f"\n=== Resume de l'analyse ===")
print(f"Echecs de connexion : {compteur_echec_connexion}")
print(f"Echecs d'authentification : {compteur_echec_auth}")
print(f"Utilisateurs inconnus : {compteur_utilisateur_inconnu}")
print(f"Total : {len(entrees_suspectes)} entrees suspectes")

# Etape 6 : Exporter en CSV
import csv
with open("logs_suspects.csv", "w", newline="", encoding="utf-8") as fichier_csv:
    writer = csv.writer(fichier_csv)
    writer.writerow(["Type d'evenement", "Ligne de log"])
    writer.writerows(entrees_suspectes)

print("\nResultats sauvegardes dans logs_suspects.csv")