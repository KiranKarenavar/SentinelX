import requests
import urllib3
from typing import Any

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


class WazuhClient:

    def __init__(
        self,
        manager_host: str = "https://127.0.0.1:55000",
        manager_username: str = "wazuh-wui",
        manager_password: str = "wazuh-wui",
        indexer_host: str = "https://127.0.0.1:9200",
        indexer_username: str = "admin",
        indexer_password: str = "Kiran-123"
    ):

        self.manager_host = manager_host.rstrip("/")

        self.manager_username = manager_username
        self.manager_password = manager_password

        self.indexer_host = indexer_host.rstrip("/")

        self.indexer_username = indexer_username
        self.indexer_password = indexer_password

        self.token = None

    def authenticate(self) -> str:

        response = requests.get(
            f"{self.manager_host}/security/user/authenticate?raw=true",
            auth=(
                self.manager_username,
                self.manager_password
            ),
            verify=False,
            timeout=10
        )

        response.raise_for_status()

        self.token = response.text.strip()

        return self.token

    def get_agents(self) -> dict[str, Any]:

        if not self.token:
            self.authenticate()

        response = requests.get(
            f"{self.manager_host}/agents",
            headers={
                "Authorization": f"Bearer {self.token}"
            },
            verify=False,
            timeout=10
        )

        response.raise_for_status()

        return response.json()

    def get_alerts(
        self,
        limit: int = 20
    ) -> dict[str, Any]:

        response = requests.get(
            f"{self.indexer_host}/wazuh-alerts-*/_search",
            auth=(
                self.indexer_username,
                self.indexer_password
            ),
            params={
                "size": limit,
                "sort": "timestamp:desc"
            },
            verify=False,
            timeout=10
        )

        response.raise_for_status()

        data = response.json()

        alerts = []

        for hit in data.get("hits", {}).get("hits", []):

            source = hit.get("_source", {})

            alerts.append(source)

        return {
            "data": {
                "affected_items": alerts
            }
        }
