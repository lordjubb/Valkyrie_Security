# Valkyrie_Security


Ce projet est une suite d'outils de sécurité permettant de scanner des réseaux, d'exploiter des vulnérabilités, de tester des connexions FTP anonymes et d'analyser la force des mots de passe.

## Fonctionnalités

- Scan des ports et détection des vulnérabilités (CVEs)
- Scan des réseaux locaux
- Exploitation de vulnérabilités avec Metasploit
- Vérification de la force des mots de passe
- Test des connexions SSH avec Hydra
- Test des connexions FTP anonymes

## Installation

Ce projet est conçu pour fonctionner sur Kali Linux. Assurez-vous que vous utilisez une machine sous Kali Linux avant de commencer l'installation.

1. Clonez ce dépôt GitHub :
    ```bash
    git clone https://github.com/votre-utilisateur/votre-repo.git
    cd votre-repo
    ```

2. Installez les dépendances Python :
    ```bash
    pip install -r requirements.txt
    ```

3. Assurez-vous d'avoir les outils externes suivants installés :
    - Nmap
    - Hydra
    - Metasploit

    Vous pouvez les installer avec les commandes suivantes si ce n'est pas déjà fait :
    ```bash
    sudo apt update
    sudo apt install -y nmap hydra metasploit-framework
    ```

## Utilisation

Pour utiliser la suite d'outils de sécurité, exécutez le script principal :
```bash
python Valkiry_Security.py

by JULIEN GASTAL
