import ipaddress


def ipInput():
    while True:
        try:
            ip = input("Veuillez entrez une ip:")
            return ipaddress.ip_address(ip)
        except ValueError:
            print("L'ip n'est pas valideS")

def maskInput(ip):
    while True :
        try:
            masque = input("Veuillez entrez un masque:")
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
        broadcast_binaire = reseau_binaire | (~masque_binaire & 0xFFFFFFFF)
        sous_reseau_binaire = (ip_binaire & masque_binaire) + 1
        

        # Convertir les résultats binaires en adresses IPv4
        reseau = ipaddress.IPv4Address(reseau_binaire)
        broadcast = ipaddress.IPv4Address(broadcast_binaire)
        sous_reseau = ipaddress.IPv4Address(sous_reseau_binaire) 

        return str(reseau), str(broadcast), str(sous_reseau)

    except ipaddress.AddressValueError:
        return "Adresse IP ou masque invalide."



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
        resultats = calculer_adresses(ip, masque)

        print ('Voulez-vous une découpe en sous-réseaux ? (oui/non) ')
        reponse = input()

        if reponse=="oui":
            if isinstance(resultats, tuple):
                adresse_reseau, adresse_broadcast, adresse_sous_reseau = resultats
                print(f"Adresse du réseau: {adresse_reseau}")
                print(f"Adresse de broadcast: {adresse_broadcast}")
                print(f"Adresse du sous-réseau: {adresse_sous_reseau}")
            
            else:
                print(resultats)

        else:
           
            if isinstance(resultats, tuple):
                adresse_reseau, adresse_broadcast, adresse_sous_reseau = resultats
                print(f"Adresse du réseau: {adresse_reseau}")
                print(f"Adresse de broadcast: {adresse_broadcast}")
                
            
            else:
                print(resultats)
            

    elif choix == "2":
            print()
    elif choix == "3":
            print()
    elif choix == "4":
        break

    else:
        print("Option invalide. Choisissez 1, 2, 3 ou 4.")   


