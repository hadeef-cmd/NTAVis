import requests

TOKEN = "8474674007:AAGna-oOAd6R9vgcmGPDjGPCJP93vSlLyDs"  
CHAT_ID = "827022419"

def send_telegram_alert(message):
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    data = {"chat_id": CHAT_ID, "text": message}
    requests.post(url, data=data)

# Example usage
send_telegram_alert("🚨 Threat detected: SYN Flood from 192.168.1.10")
