import os

import httpx
from dotenv import load_dotenv


load_dotenv()


WAZUH_API_URL = os.getenv(
    "WAZUH_API_URL",
    "https://127.0.0.1:55000",
)

WAZUH_API_USER = os.getenv(
    "WAZUH_API_USER"
)

WAZUH_API_PASSWORD = os.getenv(
    "WAZUH_API_PASSWORD"
)


class WazuhClient:
    """
    Client for communicating with the Wazuh Manager API.
    """

    def __init__(self):
        self.base_url = WAZUH_API_URL.rstrip("/")
        self.username = WAZUH_API_USER
        self.password = WAZUH_API_PASSWORD
        self.token = None

    async def authenticate(self):
        """
        Authenticate with Wazuh API.
        """

        if not self.username or not self.password:
            raise RuntimeError(
                "Wazuh API credentials are not configured"
            )

        url = (
            f"{self.base_url}"
            "/security/user/authenticate"
            "?raw=true"
        )

        try:
            async with httpx.AsyncClient(
                verify=False,
                timeout=20,
            ) as client:

                response = await client.post(
                    url,
                    auth=(
                        self.username,
                        self.password,
                    ),
                )

            response.raise_for_status()

            self.token = response.text.strip()

            if not self.token:
                raise RuntimeError(
                    "Wazuh API token was not returned"
                )

            return self.token

        except httpx.HTTPError as exc:
            raise RuntimeError(
                f"Wazuh authentication failed: {exc}"
            ) from exc

    async def get_agents(
        self,
        limit: int = 10,
    ):
        """
        Retrieve Wazuh agents.
        """

        if not self.token:
            await self.authenticate()

        url = (
            f"{self.base_url}"
            "/agents"
        )

        headers = {
            "Authorization": (
                f"Bearer {self.token}"
            )
        }

        params = {
            "limit": limit,
        }

        try:
            async with httpx.AsyncClient(
                verify=False,
                timeout=20,
            ) as client:

                response = await client.get(
                    url,
                    headers=headers,
                    params=params,
                )

            response.raise_for_status()

            return response.json()

        except httpx.HTTPError as exc:
            raise RuntimeError(
                f"Failed to retrieve Wazuh agents: {exc}"
            ) from exc

    async def get_manager_info(self):
        """
        Retrieve Wazuh manager information.
        """

        if not self.token:
            await self.authenticate()

        url = (
            f"{self.base_url}"
            "/manager/info"
        )

        headers = {
            "Authorization": (
                f"Bearer {self.token}"
            )
        }

        try:
            async with httpx.AsyncClient(
                verify=False,
                timeout=20,
            ) as client:

                response = await client.get(
                    url,
                    headers=headers,
                )

            response.raise_for_status()

            return response.json()

        except httpx.HTTPError as exc:
            raise RuntimeError(
                f"Failed to retrieve manager information: {exc}"
            ) from exc
