import json
import httpx


API_URL = (
    "http://127.0.0.1:8000"
    "/api/threat-intelligence/analyze/8.8.8.8"
)


def main():
    print("=" * 60)
    print("SENTINELX PHASE 3 API TEST")
    print("=" * 60)

    print()
    print("IOC:")
    print("8.8.8.8")

    print()
    print("Calling SentinelX API...")

    try:

        response = httpx.get(
            API_URL,
            timeout=120.0,
        )

        print()
        print("HTTP Status:")
        print(response.status_code)

        response.raise_for_status()

        result = response.json()

        print()
        print("API RESPONSE:")
        print(
            json.dumps(
                result,
                indent=4,
            )
        )

        print()
        print("=" * 60)
        print("PHASE 3 API TEST COMPLETED")
        print("=" * 60)

    except httpx.HTTPStatusError as error:

        print()
        print("API returned an HTTP error:")
        print(error)

        print()
        print("Response:")
        print(error.response.text)

    except Exception as error:

        print()
        print("API connection failed:")
        print(error)


if __name__ == "__main__":
    main()
