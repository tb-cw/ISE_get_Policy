import requests
import json
from requests.auth import HTTPBasicAuth

# ==== Konfiguration ====
ISE_HOST = "https://<ISE-IP-or-Hostname>"
USERNAME = "admin"
PASSWORD = "your_password"
OUTPUT_FILE = "authorization_policies.json"

# ==== API-Endpunkte ====
AUTHZ_POLICY_URL = f"{ISE_HOST}:9060/ers/config/authorizationpolicy"

# ==== API-Request ====
def get_authorization_policies():
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    try:
        response = requests.get(
            AUTHZ_POLICY_URL,
            headers=headers,
            auth=HTTPBasicAuth(USERNAME, PASSWORD),
            verify=False  # Nur für Tests, bei echten Deployments Zertifikat prüfen!
        )
        response.raise_for_status()
        data = response.json()
        return data
    except requests.exceptions.RequestException as e:
        print(f"[!] Fehler beim Abrufen: {e}")
        return None

# ==== Hauptlogik ====
if __name__ == "__main__":
    print("[*] Rufe Authorization Policies von Cisco ISE ab ...")
    policies = get_authorization_policies()

    if policies:
        with open(OUTPUT_FILE, "w") as f:
            json.dump(policies, f, indent=4)
        print(f"[✓] Export erfolgreich gespeichert in: {OUTPUT_FILE}")
    else:
        print("[!] Keine Daten exportiert.")
