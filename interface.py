import tkinter as tk

def login():
    username = username_entry.get()
    password = password_entry.get()
    
    
    if username == "votre_utilisateur" and password == "votre_mot_de_passe":
        message_label.config(text="Connexion réussie!")
    else:
        message_label.config(text="Échec de la connexion. Veuillez réessayer.")

root = tk.Tk()
root.title("Fenêtre de Connexion")
root.geometry("350x200")

username_label = tk.Label(root, text="Nom d'utilisateur:")
username_entry = tk.Entry(root)
password_label = tk.Label(root, text="Mot de passe:")
password_entry = tk.Entry(root, show="*")  
login_button = tk.Button(root, text="Se connecter", command=login)
message_label = tk.Label(root, text="")

username_label.pack()
username_entry.pack()
password_label.pack()
password_entry.pack()
login_button.pack()
message_label.pack()

root.mainloop()
