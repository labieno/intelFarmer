import requests
import re
from datetime import datetime, timedelta, timezone, date
import os
from src.helpers import write_pdf_to_directory

def setup_MITRE_file():
    # Import MITRE and get groups
    print("[+] Connecting to MITRE database...")
    from mitreattack.stix20 import MitreAttackData

    # https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
    mitre_attack_data = MitreAttackData("enterprise-attack.json")
    groups = mitre_attack_data.get_groups()
    #print(groups)
    APTS = {}
    for group in groups:
        try:
            APTS[group['name']] = group['aliases']
        except:
            pass
    
    return APTS

# List APT groups
def retrieve_groups():
    APTS = setup_MITRE_file()
    print("[+] Listing APT groups stored in database:")
    for group in APTS.keys():
        print(f"- {group}")

def get_group_info(name):

    print("[+] Connecting to MITRE database...")
    from mitreattack.stix20 import MitreAttackData

    # https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
    mitre_attack_data = MitreAttackData("enterprise-attack.json")
    #groups = mitre_attack_data.get_groups()
    #print(json.dumps(groups[0], indent=4, ensure_ascii=False))
    found = 0
    #print(APTS)
    groups = mitre_attack_data.get_groups_by_alias(name)
    if len(groups) >1:
        print(f"[*] Warning: There are more than one group with the name {name}: ")
        for group in groups:
            print(f"    {group.name}")
        print()
    #print(groups)
    tools_by_group = []
    malware_by_group = []

    #group = groups[1]
    for group in groups:
        aliases = ", ".join(group.aliases)
        print(f"    === {group.name} ===\n\n[+] Aliases:\n{aliases}\n\n[+] Description:\n{group.description}")
        software_used = mitre_attack_data.get_software_used_by_group(group.id)
        #print(software_used)
        #print(list(group.keys()))
        for s in software_used:
            software = s["object"]
            if software.labels[0] == "malware":
                malware_by_group.append(software)
            elif software.labels[0] == "tool":
                tools_by_group.append(software)
            #print(f"* {software.id} {software.name} {software.revoked} {software.labels}")
            
            #print(list(s['object'].keys()))
            #print(s['relationships'])  Aliases: {software.aliases}
        #print("===================")
        print()
        #print(len(software_used))
    print("\n")
    print("[+] TOOLSET:")
    for software in tools_by_group + malware_by_group:
        print(f"* {software.name:<15} == Label: {software.labels[0]:<7} == Created: {software.created} == Modified: {software.created}")


def extract_APT_reports(group):
    
    APTS = setup_MITRE_file()
    found = 0
    #print(APTS)
    for apt in APTS.keys():
        #print(APTS[apt])
        if group in APTS[apt]:
            found = 1
            apt_group = apt
            aliases = APTS[apt]
            break
    
    if found == 0:
        print("     [-] APT group not in database. If you want to list all the APT groups stored: \"python intelFarmer.py -l\"")
        # retrieve_groups() ?
        print("[+] Exiting...")
        return 0
    
    print(f"[+] Database read. Group found as {apt_group}.")


    """
    # find aliases in titles
    # HAY QUE DIVIDIR ENTRE FEEDS DE APTS (vx-underground, buenas fuentes de intel, etc.) Y GENÉRICOS (hackernews)
    # ENTRE LOS FEEDS DE APTS hay que lanzar esta búsqueda
    for source in rss_feed_list:
        feed = feedparser.parse(source[0])
        print("========================================", source[1], "========================================")
        for entry in feed.entries:
            print(entry.title)
            for alias in aliases:
                if alias in entry.title:

                    print("\033[0;34m", entry.published, "==========", entry.title, "==========>", entry.link, "\033[0m")"
    """


# Otra funcion donde se busque solo el nombre de un apt (y sus alias y familias de malware) en VX-UNDERGROUND
# VX-UNDERGROUND
def extract_vxUndergroundReports():

    # Crear la lista de años desde 2010 hasta el actual
    years = list(range(2010, datetime.now().year + 1))
    years = [2014]
    for year in years:
        #if year == "2013":
            #return
        url = "https://vx-underground.org/APTs/" + str(year)

        # Check all folders are setup
        directory = os.path.abspath(".\\vx_underground_reports\\" + str(year) + "\\")

        if not os.path.exists(directory):
            os.mkdir(directory)
        else:
            print(directory + " already created")

        if  os.listdir(directory):
            print(directory + " NO vacio. NOT STOPPING...")
            #continue

        print(directory + " vacio. Searching for pdfs...")
        
        # Get pdfs url
        response = requests.get(url)
        #print(response)

        # Regex for strings in html containing the pdf titles
        regex_list = re.findall("<p class=\"text-white text-sm truncate\">.*", response.text)

        # parse pdf TITLES from the strings
        pdf_title_list = []
        for string in regex_list:
            pdf_title_list.append(string.replace("<p class=\"text-white text-sm truncate\">","").replace("</p>",""))

        # Download pdfs
        # download_pdf(webpage_url , pdf_title_list, file_directory)

        print(pdf_title_list)


        pdf_filename_list = []
        pdf_download_url_list = []

        for pdf_title in pdf_title_list:

            pdf_filename_list.append(pdf_title.split(" - ")[1]\
            .replace("\\","").replace("/","").replace(":","")\
            .replace("*","").replace("?","").replace("\"","")\
            .replace("<","").replace(">","").replace("|", "") + ".PDF")

            pdf_title_url = url + "/" + pdf_title.replace(" ", "%20").replace("&#39;","'")+ "/Paper"

            try:

                response = requests.get(pdf_title_url)

                pdf_download_url = re.findall("href=.*.pdf|href=.*.PDF", response.text)[0].replace("href=\"","")

                print(pdf_download_url.replace("&#39;","'"))

                pdf_download_url_list.append(pdf_download_url.replace("&#39;","'"))

            except IndexError:
                print("Error: "  + pdf_title_url + " =======> ")
                print(re.findall("href=.*.pdf|href=.*.PDF", response.text))
                pass

        print("Total number of PDF = ", len(pdf_download_url_list))
        print("\n")
        print("##############################################################################")
        print("\n")
        print("Saving PDF......")

        for i in range(len(pdf_download_url_list)):

            #response = requests.get(pdf_download_url_list[i], stream=True)
            #response.raise_for_status()  # Raise an exception for unsuccessful downloads

            #filename = pdf_filename_list[i]
            filename = pdf_title_list[i] + ".pdf"

            try:
                response = requests.get(pdf_download_url_list[i], stream=True)
                file_path = os.path.join(directory, filename)
                
                if os.path.exists(file_path):
                    raise FileExistsError(f"El archivo '{filename}' ya existe en '{directory}'.")

                write_pdf_to_directory(response, filename, directory)
                print(f"Archivo '{filename}' guardado correctamente en '{directory}'.")

            except FileExistsError as e:
                print(f"Error: {e}")
            except Exception as e:
                print(filename + " " + str(year))
                print(f"Ocurrió un error inesperado: {e}")