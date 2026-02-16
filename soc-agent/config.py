import os
from dotenv import load_dotenv

load_dotenv(dotenv_path='../.env')

class Config:
    AGENT_PORT = int(os.getenv('AGENT_PORT', 8000))
    NODE_PORT = int(os.getenv('NODE_PORT', 3000))
    DEBUG = os.getenv('DEBUG', 'true').lower() == 'true'
    MCP_URL = f"http://localhost:{NODE_PORT}"

    SOC_RULES = [
        "failed login burst",
        "powershell encoded command",
        "multiple process spawn"
    ]

    MITRE_MAPPINGS = {
        "failed login burst": {
            "technique": "T1110",
            "tactic": "Credential Access",
            "name": "Brute Force"
        },
        "powershell encoded command": {
            "technique": "T1059.001",
            "tactic": "Execution",
            "name": "PowerShell"
        },
        "multiple process spawn": {
            "technique": "T1059",
            "tactic": "Execution",
            "name": "Command and Scripting Interpreter"
        }
    }

config = Config()
