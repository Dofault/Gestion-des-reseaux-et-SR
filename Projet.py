import ipaddress


def ipEntered():
    while True:
        try:
            ip = input("Veuillez entrez une ip:")
            return ipaddress.ip_address(ip)
        except ValueError:
            print("L'ip n'est pas valideS")
          





while True:
    print("Menu:")
    print("1. Calculer l'adresse de réseau, l'adresse de broadcast et l'adresse du sous-réseau")
    print("2. Vérifier si une adresse IP appartient à un réseau")
    print("3. Calculer le plan d'adressage")
    print("4. Quitter")

    choix = input("Choisissez une option (1/2/3/4): ")

    if choix == "1":
        # Demandez à l'utilisateur d'entrer l'adresse IP et le masque
        ip=ipEntered()
        masque = input()
        print ('Voulez-vous une découpe en sous-réseaux ? (oui/non) ')
        reponse = input()

    if reponse=="oui":
        print ('Veuillez entrez un masque ')
        masque = input()

    else:
        print(ip)
        print (masque)
        resultats = calculer_adresses(adresse_ip, masque)
    elif choix == "2":

    elif choix == "3":

    elif choix == "4":
        break

    else:
        print("Option invalide. Choisissez 1, 2, 3 ou 4.")   


