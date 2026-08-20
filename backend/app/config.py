import os

from dotenv import load_dotenv


load_dotenv()


# =========================
# Database
# =========================

DATABASE_URL = os.getenv("DATABASE_URL")


# =========================
# Threat Intelligence
# =========================

OTX_API_KEY = os.getenv("OTX_API_KEY")

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

THREATFOX_AUTH_KEY = os.getenv("THREATFOX_AUTH_KEY")

VT_API_KEY = os.getenv("VT_API_KEY")


# =========================
# Wazuh
# =========================

WAZUH_API_URL = os.getenv("WAZUH_API_URL")

WAZUH_API_USER = os.getenv("WAZUH_API_USER")

WAZUH_API_PASSWORD = os.getenv("WAZUH_API_PASSWORD")


# =========================
# AI
# =========================

AI_PROVIDER = os.getenv("AI_PROVIDER")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
