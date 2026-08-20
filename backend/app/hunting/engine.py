from datetime import datetime
from app.hunting.normalizer import normalize_hunt_result
import requests
import urllib3

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


class HuntingEngine:

    def hunt_destination_ip(
        self,
        ip: str,
        size: int = 100
    ):

        query = {
            "query_string": {
                "query": (
                    f'data.win.eventdata.destinationIp:"{ip}"'
                )
            }
        }

        return self.hunt(
            query,
            size
        )


    def hunt_process(
        self,
        process_name: str,
        size: int = 100
    ):

        query = {
            "query_string": {
                "query": (
                    f'data.win.eventdata.image:"*{process_name}*"'
                )
            }
        }

        return self.hunt(
            query,
            size
        )


    def hunt_ioc_time_range(
        self,
        ioc: str,
        start_time: str,
        end_time: str,
        size: int = 100
    ):

        query = {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": f'"{ioc}"'
                        }
                    },
                    {
                        "range": {
                            "@timestamp": {
                                "gte": start_time,
                                "lte": end_time
                            }
                        }
                    }
                ]
            }
        }

        return self.hunt(
            query,
            size
        )


    def hunt_time_range(
        self,
        start_time: str,
        end_time: str,
        size: int = 100
    ):

        query = {
            "range": {
                "@timestamp": {
                    "gte": start_time,
                    "lte": end_time
                }
            }
        }

        return self.hunt(
            query,
            size
        )


    def hunt_host(
        self,
        hostname: str,
        size: int = 100
    ):

        query = {
            "match": {
                "agent.name": hostname
            }
        }

        return self.hunt(
            query,
            size
        )


    def hunt_ioc(
        self,
        ioc: str,
        size: int = 100
    ):

        query = {
            "query_string": {
                "query": (
                    f'"{ioc}"'
                )
            }
        }

        return self.hunt(
            query,
            size
        )


    def hunt(
        self,
        query: dict,
        size: int = 50
    ):

        data = self.search(
            query,
            size
        )

        hits = data.get(
            "hits",
            {}
        ).get(
            "hits",
            []
        )

        return [
            normalize_hunt_result(hit)
            for hit in hits
        ]

    def __init__(
        self,
        indexer_host="https://127.0.0.1:9200",
        username="admin",
        password="admin"
    ):

        self.indexer_host = indexer_host.rstrip("/")
        self.username = username
        self.password = password

    def search(
        self,
        query: dict,
        size: int = 50
    ):

        response = requests.post(
            f"{self.indexer_host}/wazuh-alerts-*/_search",
            auth=(
                self.username,
                self.password
            ),
            json={
                "size": size,
                "sort": [
                    {
                        "timestamp": {
                            "order": "desc"
                        }
                    }
                ],
                "query": query
            },
            verify=False,
            timeout=15
        )

        response.raise_for_status()

        data = response.json()

        return data

    def search_text(
        self,
        field: str,
        value: str,
        size: int = 50
    ):

        query = {
            "match": {
                field: value
            }
        }

        return self.search(
            query,
            size
        )

    def search_ip(
        self,
        ip: str,
        size: int = 50
    ):

        query = {
            "query_string": {
                "query": (
                    f'"{ip}"'
                )
            }
        }

        return self.search(
            query,
            size
        )
