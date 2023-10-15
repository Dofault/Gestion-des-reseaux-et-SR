
import ipaddress
import math
from operator import xor
import sqlite3
import bcrypt
conn = sqlite3.connect("securityDB.db")
cur = conn.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS Users (username TEXT NOT NULL, password_hash TEXT NOT NULL)")

class ExceptionClassful(Exception):
    def __init__(self, message):
        super().__init__(message)

def hash_password(password):
    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(password.encode(), salt)
    return password_hash

def add_user(username, password):
    password_hash = hash_password(password)
    cur.execute("INSERT INTO Users (username, password_hash) VALUES (?, ?)", (username, password_hash.decode()))
    conn.commit()

def check_password(username, password):
    cur.execute("SELECT password_hash FROM Users WHERE username = ?", (username,))
    result = cur.fetchone()
    if result:
        stored_hash = result[0].encode()
        return bcrypt.checkpw(password.encode(), stored_hash)
    return False

def remove_user(username, password):
    cur.execute("DELETE FROM Users WHERE username = ?", (username,))
    conn.commit()


def ipInput():
    while True:
        try:
            ip = input("\nVeuillez entrez une ip:")
            first_octet = int(str(ip).split('.')[0])
            if 1 <=  223:
                return ipaddress.ip_address(ip)
            else:
                raise ExceptionClassful("Cette ip n'est pas une classful")
            
        except ValueError:
            print("\nL'ip n'est pas valideS")

        except ExceptionClassful:
            print("Cette ip n'est pas une classful")

def maskInput(ip, decoupe_sous_reseaux):
    if decoupe_sous_reseaux:
        while True:
            try:
                masque = input("\nVeuillez entrez un masque:")
                mask = ipaddress.IPv4Network(f"{ip}/{masque}", strict=False)
                return mask.netmask  # vérification si la variable est un masque
            except (ipaddress.AddressValueError, ValueError):
                print("\nLe masque n'est pas valide")
    else:
        # Calculer automatiquement le masque en fonction de la classe de sous-réseau
        first_octet = int(str(ip).split('.')[0])
        if 1 <= first_octet <= 126:
            mask = '255.0.0.0'  # Classe A
        elif 128 <= first_octet <= 191:
            mask = '255.255.0.0'  # Classe B
        elif 192 <= first_octet <= 223:
            mask = '255.255.255.0'  # Classe C
        else:
            mask = '255.255.255.0'  # Par défaut, classe C

        print(f"Masque attribué automatiquement : {mask}")
        return ipaddress.IPv4Network(f"{ip}/{mask}", strict=False).netmask


def calculer_adresses(ip_str, masque_str):
    try:
        # Valider l'adresse IP et le masque
        ip = ipaddress.IPv4Address(ip_str)
        masque = ipaddress.IPv4Address(masque_str)

        # Obtenir la représentation binaire des adresses IP et des masques
        ip_binaire = int(ip)
        masque_binaire = int(masque)

        reseau_binaire = ip_binaire & masque_binaire
        broadcast_binaire = reseau_binaire | (~masque_binaire & 0xFFFFFFFF)  # ~ transforme les 1 en 0 et 0 en 1
        sous_reseau_binaire = (reseau_binaire) + 1

        # Calculer le nombre de bits à zéro dans le masque de sous-réseau
        bits_a_zero = bin(masque_binaire).count('0') - 1  # -1 car il compte aussi le zéro de 0b "0b11111111111111111111111100000000"
        sous_reseaux_maximum_possibles = (2 ** (bits_a_zero - 2)) - 1
        ips_maximum_possible_par_sous_reseaux = int(((2 ** (bits_a_zero)) - 4)/2)

        # print("sous_reseaux_possibles_maximum : ", sous_reseaux_maximum_possibles, "ips_possible_par_sous_reseaux_maximum :", ips_maximum_possible_par_sous_reseaux)

        # Convertir les résultats binaires en adresses IPv4
        reseau = ipaddress.IPv4Address(reseau_binaire)
        broadcast = ipaddress.IPv4Address(broadcast_binaire)
        sous_reseau = ipaddress.IPv4Address(sous_reseau_binaire)

        return str(reseau), str(broadcast), str(sous_reseau), sous_reseaux_maximum_possibles, ips_maximum_possible_par_sous_reseaux

    except ipaddress.AddressValueError:
        return "Adresse IP ou masque invalide."

def calculSR_selonIPS(adresse_reseau, masque, nbips ):


    nbZero = (bin(int(masque)).count('0') - 1)

    for i in range(nbZero) :
        val = 2**i
        if(val > nbips+1) :
            break

    pas = val
    masque = ipaddress.IPv4Address(masque)
    val = (~(val-1)& 0xFFFFFFFF)
    nouv_masque=ipaddress.IPv4Address(int(val) | int(masque))
    #print("masque : ", masque, "val : ", val, "masque : ", masque, "nouveau masque des sous reseaux : ",nouv_masque)
    x=xor(int(nouv_masque), int(masque))
    #print("x:", x)
    nbDeUnPourLeNombreDeSousReseau = (bin(int(x)).count('1'))
    nbSR=2**nbDeUnPourLeNombreDeSousReseau

    #nouvMasqueSR, pas, nbSR = calculSR_selonIPS(adresse_reseau, masque, nbips)
    return str(nouv_masque), pas, nbSR

def calculSR(adresse_reseau, masque, nbSR):
    nombre_de_bits_pour_representer_nbSR = int(math.ceil(math.log2(nbSR)))

    x = 0
    nbZero = (bin(int(masque)).count('0') - 1)

    for i in range(0, nombre_de_bits_pour_representer_nbSR):
        pas = 2 ** (nbZero - 1 - (i))
        x += pas

    msk_binaire = int(x)
    masque_binaire = int(masque)
    nouveau_masque = ipaddress.IPv4Address(msk_binaire | masque_binaire)

    return nouveau_masque, pas

def verifier_appartenance(ip_str, reseau_str, masque_str):
    try:
        # Valider l'adresse IP et le réseau
        ip = ipaddress.IPv4Address(ip_str)
        reseau = ipaddress.IPv4Network(f"{reseau_str}/{masque_str}", strict=False)

        # Vérifier si l'adresse IP appartient au réseau
        if ip in reseau:
            return f"L'adresse IP {ip_str} appartient au réseau {reseau_str}."
        else:
            return f"L'adresse IP {ip_str} n'appartient pas au réseau {reseau_str}."

    except ipaddress.AddressValueError:
        return "Adresse IP, masque ou réseau invalide."

# Authentification
while True:
    print("\n--------------------")
    print("| Authentification |")
    print("--------------------\n")
    print("1. Se connecter\n")
    print("2. Ajouter un utilisateur\n")
    print("3. Supprimer un utilisateur\n")
    print("4. Quitter\n")

    auth_choice = input("\nChoisissez une option (1/2/3/4): ")
    print("\n")

    if auth_choice == "1":
        username = input("\nNom d'utilisateur : ")
        password_hash = input("\nMot de passe : ")
        if check_password(username, password_hash):
            print("\nConnexion réussie en tant qu'utilisateur", username , "\n")
            break
        else:
            print("\nÉchec de la connexion. Vérifiez vos informations d'identification.")

    elif auth_choice == "2":
        username = input("\nNom d'utilisateur : ")
        password_hash = input("\nMot de passe : ")
        add_user(username, password_hash)
        print("\nUtilisateur ajouté avec succès.\n")

    elif auth_choice == "3":
        username = input("\nNom d'utilisateur : ")
        password_hash = input("\nMot de passe : ")
        if check_password(username, password_hash):
            remove_user(username, password_hash)
            print("\nUtilisateur supprimé avec succès.")
        else:
            print("\nÉchec de la suppression. Vérifiez vos informations d'identification.")

    elif auth_choice == "4":
        print("\nAu revoir !\n")
        exit()

    else:
        print("\nOption invalide. Choisissez 1, 2, 3 ou 4.")

# Menu principal après l'authentification
while True:
    print("\n----------------------")
    print("|   Menu principal   |")
    print("----------------------\n")
    print("\n1. Calculer l'adresse de réseau, l'adresse de broadcast et l'adresse du sous-réseau\n")
    print("2. Vérifier si une adresse IP appartient à un réseau\n")
    print("3. Calculer le plan d'adressage\n")
    print("4. Quitter\n")

    choix = input("\nChoisissez une option (1/2/3/4): ")
    print("\n")

    if choix == "1":
    # Demandez à l'utilisateur d'entrer l'adresse IP
        ip = ipInput()
        print("\n")
        while True:
            print('\nVoulez-vous une découpe en sous-réseaux ? (oui/non) \n')
            print("1. Oui\n")
            print("2. Non\n")
            reponse = input("\nChoisissez une option (1/2): ")
            print("\n")

            if reponse == "1":
                # L'utilisateur souhaite découper en sous-réseaux
                masque = maskInput(ip, True)
                print("\n")
                resultats = calculer_adresses(ip, masque)
                if isinstance(resultats, tuple):
                    adresse_reseau, adresse_broadcast, adresse_sous_reseau, sous_reseaux_maximum_possibles, ips_maximum_possible_par_sous_reseaux = resultats
                    print(f"Adresse IP introduite: {ip}")
                    print(f"Masque du réseau: {masque}")
                    print(f"Adresse réseau: {adresse_reseau}")
                    print(f"Adresse de broadcast: {adresse_broadcast}")
                    print(f"1er IP du premier sous-réseau: {adresse_sous_reseau}")
                    print(f"Nombre de sous-réseaux maximum possibles : {sous_reseaux_maximum_possibles}")
                    print(f"Nombre d'IPs maximum possibles par sous-réseau : {ips_maximum_possible_par_sous_reseaux}")
                else:
                    print(resultats)
                break
            elif reponse == "2":
                # L'utilisateur ne souhaite pas découper en sous-réseaux
                masque = maskInput(ip, False)
                resultats = calculer_adresses(ip, masque)
                if isinstance(resultats, tuple):
                    adresse_reseau, adresse_broadcast, adresse_sous_reseau, sous_reseaux_maximum_possibles, ips_maximum_possible_par_sous_reseaux = resultats
                    print(f"Adresse IP introduite: {ip}")
                    print(f"Masque du réseau: {masque}")
                    print(f"Adresse réseau: {adresse_reseau}")
                    print(f"Adresse de broadcast: {adresse_broadcast}")
                else:
                    print(resultats)
                break
            else:
                print("\nOption invalide. Choisissez 1 ou 2.")


    elif choix == "2":
        # Demandez à l'utilisateur d'entrer l'adresse IP, le réseau et le masque
        ip = ipInput()
        print("\n")
        masque = maskInput(ip, True)
        print("\n")
        reseau = input("\nEntrez l'adresse du réseau : ")
        print("\n")
        resultat = verifier_appartenance(ip, reseau, masque)
        print(resultat)

    elif choix == "3":
        # Demandez à l'utilisateur d'entrer l'adresse IP et le masque
        ip = ipInput()
        print("\n")
        masque = maskInput(ip, False)
        sous_reseaux_maximum_possibles = int()
        ips_maximum_possible_par_sous_reseaux = int()
        resultats = calculer_adresses(ip, masque)
        if isinstance(resultats, tuple):

            adresse_reseau, adresse_broadcast, adresse_sous_reseau, sous_reseaux_maximum_possibles, ips_maximum_possible_par_sous_reseaux = resultats
            print(f"Adresse IP introduite: {ip}")
            print(f"Masque du réseau: {masque}")
            print(f"Adresse réseau: {adresse_reseau}")
            print(f"Adresse de broadcast: {adresse_broadcast}")

            print('\nDécoupe de sous réseau :\n')
            print("1. Connaitre le nombre d'hote possible\n")
            print("2. Definir le nombre de sous-réseaux souhaité\n")
            print("3. Definir le nombre d'IPs souhaité par sous-réseau\n")
            reponse = input("\nChoisissez une option (1/2/3): ")
            print("\n")
            if reponse == "1":  # Affichage de nombre d'Hote possible et de sous reseaux
                print(f"Nombre de sous-réseaux maximum possibles : {sous_reseaux_maximum_possibles}")
                print(f"Nombre d'Hote maximum possibles par sous-réseau : {ips_maximum_possible_par_sous_reseaux}")

            elif reponse == "2":  # découpe selon le nombre de SR
                print("max :", sous_reseaux_maximum_possibles)
                nbSR = int(input('Combien de sous-réseaux souhaitez-vous ?'))
                while nbSR > sous_reseaux_maximum_possibles:
                    nbSR = int(input("Erreur, l'adresse réseau ne peut pas accueillir autant de sous-réseaux"))

                nouvMasqueSR, pas = calculSR(adresse_reseau, masque, nbSR)

                print("| N°SR             | Adresse SR       | Adresse BC       | 1er IP           | Dernière IP      | Masque           | Pas     | Nb machines dans le SR  |")
                for i in range(nbSR):
                    adresse_reseau_actuel = ipaddress.IPv4Address(ipaddress.IPv4Address(adresse_reseau) + (pas * i))
                    broadcast = ipaddress.IPv4Address((adresse_reseau_actuel) + pas - 1)
                    derniereip = ipaddress.IPv4Address((adresse_reseau_actuel) + pas - 2)
                    print("| %16s | %16s | %16s | %16s | %16s | %16s |%8s | %23s |" % (i+1, adresse_reseau_actuel, broadcast, adresse_reseau_actuel + 1, derniereip, nouvMasqueSR,pas,pas-2))

            elif reponse == "3":
                print("max :", ips_maximum_possible_par_sous_reseaux)
                nbips = int(input("Combien d'IPs souhaitez-vous avoir par sous-réseau ? "))
                while ips_maximum_possible_par_sous_reseaux < nbips < 2:
                    nbips = int(input("Erreur, l'adresse réseau ne peut pas accueillir autant d'IPs"))

                nouvMasqueSR, pas, nbSR = calculSR_selonIPS(adresse_reseau, masque, nbips)

                print("| N°SR             | Adresse SR       | Adresse BC       | 1er IP           | Dernière IP      | Masque           | Pas     | Nb machines dans le SR  |")
                #print("| IP sous-réseau   | 1er IP           | Dernière IP      | IP de broadcast   |")
                for i in range(nbSR):
                    adresse_reseau_actuel = ipaddress.IPv4Address(ipaddress.IPv4Address(adresse_reseau) + (pas * i))
                    broadcast = ipaddress.IPv4Address((adresse_reseau_actuel) + pas -1)
                    derniereip = ipaddress.IPv4Address((adresse_reseau_actuel) + pas -2)
                    print("| %16s | %16s | %16s | %16s | %16s | %16s |%8s | %23s |" % (i+1,adresse_reseau_actuel,broadcast ,adresse_reseau_actuel + 1, derniereip,nouvMasqueSR,pas,pas-2))

            else:
                print("Option invalide. Choisissez 1, 2 ou 3.")
        else:
            print(resultats)
            
    elif choix == "4":
        print("\nAu revoir !\n")
        break

    else:
        print("\nOption invalide. Choisissez 1, 2, 3 ou 4.")