import ipaddress


def ipEntered():
    while True:
        try:
            ip = input("Veuillez entrez une ip:")
            return ipaddress.ip_address(ip)
        except ValueError:
            print("L'ip n'est pas valideS")
ip=ipEntered()            


print ('Veuillez entrez un masque ')
masque = input()


print ('Voulez-vous une découpe en sous-réseaux ? (oui/non) ')
reponse = input()

if reponse=="oui":
    print(ip)
    print(masque)
    
    print(sr)

else:
    print(ip)
    print (masque)


