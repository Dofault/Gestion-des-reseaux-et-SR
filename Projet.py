import ipaddress
import math
import sqlite3
conn = sqlite3.connect("securityDB.db")
cur = conn.cursor()
#cur.execute("Drop table Password")
#cur.execute("CREATE TABLE Password(password CHAR(60) NOT NULL DEFAULT)")


def ipInput():
    while True:
        try:
            ip = "172.16.0.0"
            #ip = input("Veuillez entrez une ip:")
            return ipaddress.ip_address(ip)
        except ValueError:
            print("L'ip n'est pas valideS")

def maskInput(ip):
    while True :
        try:
            masque = "255.255.0.0"
            #masque = input("Veuillez entrez un masque:")
            mask = ipaddress.IPv4Network(f"{ip}/{masque}", strict=False)
            return mask.netmask # verification si la variable est un masque
        except (ipaddress.AddressValueError, ValueError):
            print("Le masque n'est pas valide")
          

def calculer_adresses(ip_str, masque_str):
    try:
        # Valider l'adresse IP et le masque
        ip = ipaddress.IPv4Address(ip_str)
        masque = ipaddress.IPv4Address(masque_str)

        

        # Obtenir la représentation binaire des adresses IP et des masques
        ip_binaire = int(ip)
        masque_binaire = int(masque)

        reseau_binaire = ip_binaire & masque_binaire
        broadcast_binaire = reseau_binaire | (~masque_binaire & 0xFFFFFFFF) # ~ transforme les 1 en 0 et 0 en 1
        sous_reseau_binaire = (reseau_binaire) + 1

        # Calculer le nombre de bits à zéro dans le masque de sous-réseau
        bits_a_zero = bin(masque_binaire).count('0') - 1 # -1 car il compte aussi le zero de 0b "0b11111111111111111111111100000000"
        sous_reseaux_maximum_possibles = (2 ** (bits_a_zero-2))-1
        ips_maximum_possible_par_sous_reseaux= (2 ** (bits_a_zero))-2

        # print("sous_reseaux_possibles_maximum : ", sous_reseaux_maximum_possibles, "ips_possible_par_sous_reseaux_maximum :", ips_maximum_possible_par_sous_reseaux)
        

        # Convertir les résultats binaires en adresses IPv4
        reseau = ipaddress.IPv4Address(reseau_binaire)
        broadcast = ipaddress.IPv4Address(broadcast_binaire)
        sous_reseau = ipaddress.IPv4Address(sous_reseau_binaire) 

        return str(reseau), str(broadcast), str(sous_reseau), sous_reseaux_maximum_possibles, ips_maximum_possible_par_sous_reseaux

    except ipaddress.AddressValueError:
        return "Adresse IP ou masque invalide."
def calculSR_selonIPS(adresse_reseau, masque, nbips) :
    print("a faire")

def calculSR(adresse_reseau, masque, nbSR) :
    nombre_de_bits_pour_representer_nbSR = int(math.ceil(math.log2(nbSR)))

    
    x=0
    nbZero=(bin(int(masque)).count('0')-1)
    
    for i in range(0, nombre_de_bits_pour_representer_nbSR) :
        pas = 2**(nbZero -1- (i))
        x+= pas
        

    msk_binaire = int(x)
    masque_binaire = int(masque)
    nouveau_masque=ipaddress.IPv4Address(msk_binaire | masque_binaire)

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

while True:
    print("Menu:")
    print("1. Calculer l'adresse de réseau, l'adresse de broadcast et l'adresse du sous-réseau")
    print("2. Vérifier si une adresse IP appartient à un réseau")
    print("3. Calculer le plan d'adressage")
    print("4. Quitter")

    choix = input("Choisissez une option (1/2/3/4): ")

    if choix == "1":
        # Demandez à l'utilisateur d'entrer l'adresse IP et le masque
        ip=ipInput()
        masque = maskInput(ip)
        sous_reseaux_maximum_possibles=int()
        ips_maximum_possible_par_sous_reseaux=int()
        resultats = calculer_adresses(ip, masque)

        print ('Voulez-vous une découpe en sous-réseaux ? (oui/non) ')
        print("1. Oui")
        print("2. Non")
        reponse = input("Choisissez une option (1/2): ")

        if reponse=="1":
            if isinstance(resultats, tuple):

                adresse_reseau, adresse_broadcast, adresse_sous_reseau, sous_reseaux_maximum_possibles, ips_maximum_possible_par_sous_reseaux = resultats
                print(f"Adresse ip introduite: {ip}")
                print(f"Masque du réseau: {masque}")
                print(f"Adresse réseau: {adresse_reseau}")
                print(f"Adresse de broadcast: {adresse_broadcast}")
                #print(f"1er ip du premier sous-reseau: {adresse_sous_reseau}")
                print(f"Nombre de sous réseaux maximum possible : {sous_reseaux_maximum_possibles}")
                print(f"Nombre d'ips maximum possible par sous réseaux' : {ips_maximum_possible_par_sous_reseaux}")
            
                print ('Souhaitez-vous découper les sous reseaux en definissant :')
                print("1. Le nombre de sous réseaux souhaité")
                print("2. Le nombre d'IPS souhaité par sous réseaux")
                reponse = input("Choisissez une option (1/2): ")

                if(reponse == "1") : # decoupe selon le nombre de sr
                    nbSR=int(input('Combien de sous réseaux souhaitez-vous ?'))
                    while(nbSR >sous_reseaux_maximum_possibles) :
                        nbSR=int(input('Erreur, l\'adresse réseau ne peut pas accueillir autant de sous réseaux'))

                    nouvMasqueSR, pas = calculSR(adresse_reseau, masque, nbSR)
                    print(nouvMasqueSR, pas)
                    
                    print("| Ip sous réseau   | 1er ip           | Derniere ip      | Ip broadcast     |")
                    for i in range(nbSR):
                        adresse_reseau_actuel=ipaddress.IPv4Address(ipaddress.IPv4Address(adresse_reseau) + (pas*i))
                        broadcast= ipaddress.IPv4Address((adresse_reseau_actuel)+pas -1)
                        derniereip=ipaddress.IPv4Address((adresse_reseau_actuel)+pas -2)
                        print("| %16s | %16s | %16s | %16s |" % (adresse_reseau_actuel, adresse_reseau_actuel+1, derniereip, broadcast))
                
                if(reponse == "2") :
                    nbips=int(input('Combien d\'ips souhaitez vous avoir par sous reseaux ?'))
                    while(nbips >ips_maximum_possible_par_sous_reseaux) :
                        nbips=int(input('Erreur, l\'adresse réseau ne peut pas accueillir autant d\'ips'))

                    nouvMasqueSR, pas = calculSR_selonIPS(adresse_reseau, masque, nbips)
                    print(nouvMasqueSR, pas)
                    
                    print("| Ip sous réseau   | 1er ip           | Derniere ip      | Ip broadcast     |")
                    for i in range(nbSR):
                        adresse_reseau_actuel=ipaddress.IPv4Address(ipaddress.IPv4Address(adresse_reseau) + (pas*i))
                        broadcast= ipaddress.IPv4Address((adresse_reseau_actuel)+pas -1)
                        derniereip=ipaddress.IPv4Address((adresse_reseau_actuel)+pas -2)
                        print("| %16s | %16s | %16s | %16s |" % (adresse_reseau_actuel, adresse_reseau_actuel+1, derniereip, broadcast))

            
            else:
                print(resultats)

        else:
           
            if isinstance(resultats, tuple):
                print("t")
                
            
            else:
                print(resultats)
            

    elif choix == "2":
        # Demandez à l'utilisateur d'entrer l'adresse IP, le réseau et le masque
        ip=ipInput()
        masque = maskInput(ip)
        reseau = input("Entrez l'adresse du réseau: ")
        resultat = verifier_appartenance(ip, reseau, masque)
        print(resultat)
    elif choix == "3":
            print()
    elif choix == "4":
        break

    else:
        print("Option invalide. Choisissez 1, 2, 3 ou 4.")   


