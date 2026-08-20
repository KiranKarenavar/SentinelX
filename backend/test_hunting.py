from app.hunting.engine import HuntingEngine


def main():

    print("=" * 60)
    print("SENTINELX PHASE 6 THREAT HUNTING TEST")
    print("=" * 60)

    hunter = HuntingEngine(
        password="Kiran-123"
    )

    print("\n[1] General Event Hunt")

    results = hunter.hunt(
        {
            "match_all": {}
        },
        5
    )

    print(
        "Results:",
        len(results)
    )

    print("\n[2] Process Hunt")

    results = hunter.hunt(
        {
            "match": {
                "data.win.system.eventID": "1"
            }
        },
        5
    )

    print(
        "Process events:",
        len(results)
    )

    print("\n[3] Network Hunt")

    results = hunter.hunt(
        {
            "match": {
                "data.win.system.eventID": "3"
            }
        },
        5
    )

    print(
        "Network events:",
        len(results)
    )

    print("\n[4] IOC Hunt")

    results = hunter.hunt_ioc(
        "8.8.8.8",
        5
    )

    print(
        "IOC matches:",
        len(results)
    )

    print("\n" + "=" * 60)
    print("PHASE 6 HUNTING ENGINE TEST COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
