from fastapi import APIRouter
import os
from fastapi import APIRouter
from datetime import datetime
from cryptography.fernet import Fernet

router = APIRouter()

# Carpeta y clave para logs
LOG_DIR = "logs"
KEY_FILE = os.path.join(LOG_DIR, "key.bin")
LOG_FILE = os.path.join(LOG_DIR, "audit.log")

def get_cipher():
	if not os.path.exists(LOG_DIR):
		os.makedirs(LOG_DIR)
	if not os.path.exists(KEY_FILE):
		key = Fernet.generate_key()
		with open(KEY_FILE, "wb") as f:
			f.write(key)
	else:
		with open(KEY_FILE, "rb") as f:
			key = f.read()
	return Fernet(key)

def log_event(username, action, ip):
	cipher = get_cipher()
	now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	log_entry = f"{now}|{username}|{action}|{ip}\n"
	encrypted = cipher.encrypt(log_entry.encode())
	with open(LOG_FILE, "ab") as f:
		f.write(encrypted + b"\n")

# Endpoint para que el admin lea los logs desencriptados
@router.get("/audit/logs")
def get_logs():
	cipher = get_cipher()
	logs = []
	if os.path.exists(LOG_FILE):
		with open(LOG_FILE, "rb") as f:
			for line in f:
				try:
					decrypted = cipher.decrypt(line.strip()).decode()
					logs.append(decrypted)
				except Exception:
					continue
	return {"logs": logs}
