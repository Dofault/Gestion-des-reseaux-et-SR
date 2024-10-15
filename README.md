# Gestion du réseau et authentification des utilisateurs

Ce script offre des fonctionnalités de gestion du réseau et d'authentification des utilisateurs.  
Ce projet a été développé pour améliorer notre compréhension des concepts de réseau, y compris le sous-réseautage, l'adressage IP et, bien sûr, les processus d'authentification.

## Caractéristiques

### 1. **Authentification des Utilisateurs**
   - Utilise `bcrypt` pour hacher les mots de passe.
   - Stocke les informations d'identification des utilisateurs dans une base de données SQLite (`securityDB.db`).
   - Offre des options pour :
     - Ajouter un utilisateur.
     - Authentifier un utilisateur.
     - Supprimer un utilisateur.

### 2. **Calculs d'Adresses IP et de Sous-Réseaux**
   - Valide les adresses IP et les masques.
   - Calcule :
     - L'adresse réseau.
     - L'adresse de diffusion.
     - Les adresses de sous-réseaux.
   - Prend en charge l'attribution automatique de masques de sous-réseau en fonction de la classe (A, B, C).
   - Permet aux utilisateurs de calculer le nombre de sous-réseaux et d'adresses IP possibles.

### 3. **Interface de Connexion Tkinter**
   - Le projet contient une interface graphique `tkinter` qui n'est pas du tout terminé.

## Instructions d'Installation

1. **Installer les Dépendances Nécessaires :**  
   ```pip install bcrypt```

## Exécuter le Script :
**Pour exécuter le script :**
```python Projet.py```

## Crédits
Ce projet a été inspiré et construit sur des concepts fondamentaux en réseau. Remerciements particuliers à Hadrien pour ses contributions et ses idées.
