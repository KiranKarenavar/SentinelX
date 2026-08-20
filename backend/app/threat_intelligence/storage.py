import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import psycopg2
from psycopg2.extras import Json

from app.config import DATABASE_URL


def get_connection():
    """
    Create and return a PostgreSQL connection.
    """

    return psycopg2.connect(
        DATABASE_URL
    )


def store_ioc(
    indicator: str,
    indicator_type: str,
    source: str,
    confidence: int = 0,
    severity: str = "INFO",
    first_seen: Optional[Any] = None,
    last_seen: Optional[Any] = None,
    malware_family: Optional[str] = None,
    threat_actor: Optional[str] = None,
    mitre_technique: Optional[str] = None,
):
    """
    Insert an IOC into the iocs table.
    """

    connection = get_connection()

    try:

        cursor = connection.cursor()

        query = """
            INSERT INTO iocs (
                indicator,
                indicator_type,
                source,
                confidence,
                severity,
                first_seen,
                last_seen,
                malware_family,
                threat_actor,
                mitre_technique,
                created_at
            )
            VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s
            )
            RETURNING id
        """

        cursor.execute(
            query,
            (
                indicator,
                indicator_type,
                source,
                confidence,
                severity,
                first_seen,
                last_seen,
                malware_family,
                threat_actor,
                mitre_technique,
                datetime.now(timezone.utc),
            ),
        )

        ioc_id = cursor.fetchone()[0]

        connection.commit()

        cursor.close()

        return ioc_id

    except Exception:

        connection.rollback()

        raise

    finally:

        connection.close()


def store_threat_intelligence(
    title: str,
    source: str,
    description: Optional[str] = None,
    threat_type: Optional[str] = None,
    severity: str = "INFO",
    confidence: int = 0,
    reference_url: Optional[str] = None,
    raw_data: Optional[Dict[str, Any]] = None,
):
    """
    Store threat-intelligence information.
    """

    connection = get_connection()

    try:

        cursor = connection.cursor()

        query = """
            INSERT INTO threat_intelligence (
                title,
                source,
                description,
                threat_type,
                severity,
                confidence,
                reference_url,
                raw_data,
                created_at
            )
            VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s
            )
            RETURNING id
        """

        cursor.execute(
            query,
            (
                title,
                source,
                description,
                threat_type,
                severity,
                confidence,
                reference_url,
                Json(
                    raw_data
                    if raw_data is not None
                    else {}
                ),
                datetime.now(timezone.utc),
            ),
        )

        intelligence_id = cursor.fetchone()[0]

        connection.commit()

        cursor.close()

        return intelligence_id

    except Exception:

        connection.rollback()

        raise

    finally:

        connection.close()


def store_analysis_result(
    indicator: str,
    indicator_type: str,
    risk_result: Dict[str, Any],
    intelligence_results: Optional[list] = None,
):
    """
    Store the complete Phase 3 analysis result.
    """

    if not isinstance(
        risk_result,
        dict,
    ):

        raise ValueError(
            "risk_result must be a dictionary"
        )

    score = risk_result.get(
        "score",
        risk_result.get(
            "risk_score",
            0,
        ),
    )

    try:

        score = int(score)

    except (
        TypeError,
        ValueError,
    ):

        score = 0

    severity = str(
        risk_result.get(
            "severity",
            "INFO",
        )
    ).upper()

    verdict = str(
        risk_result.get(
            "verdict",
            "BENIGN",
        )
    ).upper()

    provider_scores = risk_result.get(
        "provider_scores",
        [],
    )

    reasons = risk_result.get(
        "reasons",
        [],
    )

    if intelligence_results is None:

        intelligence_results = []

    source = "sentinelx"

    if (
        isinstance(provider_scores, list)
        and provider_scores
    ):

        first_provider = provider_scores[0]

        if isinstance(
            first_provider,
            dict,
        ):

            source = str(
                first_provider.get(
                    "source",
                    "sentinelx",
                )
            )

    ioc_id = store_ioc(
        indicator=indicator,
        indicator_type=indicator_type,
        source=source,
        confidence=score,
        severity=severity,
    )

    analysis_data = {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "risk_score": score,
        "severity": severity,
        "verdict": verdict,
        "reasons": reasons,
        "provider_scores": provider_scores,
        "intelligence_results": intelligence_results,
        "analyzed_at": datetime.now(
            timezone.utc
        ).isoformat(),
    }

    intelligence_id = (
        store_threat_intelligence(
            title=(
                f"SentinelX IOC Analysis: "
                f"{indicator}"
            ),
            source="sentinelx",
            description=(
                f"IOC analyzed by SentinelX. "
                f"Verdict: {verdict}. "
                f"Risk score: {score}/100."
            ),
            threat_type=indicator_type,
            severity=severity,
            confidence=score,
            raw_data=analysis_data,
        )
    )

    return {
        "ioc_id": ioc_id,
        "intelligence_id": intelligence_id,
        "indicator": indicator,
        "score": score,
        "severity": severity,
        "verdict": verdict,
    }


def store_enrichment_result(
    indicator: str,
    indicator_type: str,
    risk_score: int = 0,
    severity: str = "LOW",
    verdict: str = "UNKNOWN",
    enrichment: Optional[Dict[str, Any]] = None,
):
    """
    Compatibility function used by the Phase 3
    Threat Intelligence API.

    Stores IOC enrichment and risk analysis
    using the existing SentinelX database schema.
    """

    if enrichment is None:

        enrichment = {}

    try:

        risk_score = int(
            risk_score
        )

    except (
        TypeError,
        ValueError,
    ):

        risk_score = 0

    severity = str(
        severity
    ).upper()

    verdict = str(
        verdict
    ).upper()

    # Store IOC
    ioc_id = store_ioc(
        indicator=indicator,
        indicator_type=indicator_type,
        source="sentinelx",
        confidence=risk_score,
        severity=severity,
    )

    # Store enrichment
    raw_data = {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "risk_score": risk_score,
        "severity": severity,
        "verdict": verdict,
        "enrichment": enrichment,
        "stored_at": datetime.now(
            timezone.utc
        ).isoformat(),
    }

    intelligence_id = (
        store_threat_intelligence(
            title=(
                f"SentinelX IOC Enrichment: "
                f"{indicator}"
            ),
            source="sentinelx",
            description=(
                f"IOC enrichment for {indicator}. "
                f"Verdict: {verdict}. "
                f"Risk score: {risk_score}/100."
            ),
            threat_type=indicator_type,
            severity=severity,
            confidence=risk_score,
            raw_data=raw_data,
        )
    )

    return {
        "ioc_id": ioc_id,
        "intelligence_id": intelligence_id,
        "indicator": indicator,
        "score": risk_score,
        "severity": severity,
        "verdict": verdict,
    }


def get_ioc_by_indicator(
    indicator: str,
):
    """
    Retrieve IOC records by indicator.
    """

    connection = get_connection()

    try:

        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                id,
                indicator,
                indicator_type,
                source,
                confidence,
                severity,
                first_seen,
                last_seen,
                malware_family,
                threat_actor,
                mitre_technique,
                created_at
            FROM iocs
            WHERE indicator = %s
            ORDER BY id DESC
            """,
            (indicator,),
        )

        rows = cursor.fetchall()

        cursor.close()

        return rows

    finally:

        connection.close()


def get_latest_analysis(
    indicator: str,
):
    """
    Retrieve the latest SentinelX analysis
    for an IOC.
    """

    connection = get_connection()

    try:

        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                id,
                title,
                source,
                description,
                threat_type,
                severity,
                confidence,
                reference_url,
                raw_data,
                created_at
            FROM threat_intelligence
            WHERE title = %s
            ORDER BY id DESC
            LIMIT 1
            """,
            (
                f"SentinelX IOC Analysis: "
                f"{indicator}",
            ),
        )

        row = cursor.fetchone()

        cursor.close()

        if row is None:
            return None

        return {
            "id": row[0],
            "title": row[1],
            "source": row[2],
            "description": row[3],
            "threat_type": row[4],
            "severity": row[5],
            "confidence": row[6],
            "reference_url": row[7],
            "raw_data": row[8],
            "created_at": row[9],
        }

    finally:

        connection.close()


def store_phishing_investigation(
    filename: str,
    result: Dict[str, Any],
):
    """
    Store a SentinelX phishing investigation.
    """

    connection = get_connection()

    try:

        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT COALESCE(
                MAX(id),
                0
            ) + 1
            FROM phishing_investigations
            """
        )

        next_id = cursor.fetchone()[0]

        investigation_id = (
            f"PHISH-{next_id:04d}"
        )

        email = result.get(
            "email",
            {}
        )

        headers = email.get(
            "headers",
            {}
        )

        analysis = result.get(
            "analysis",
            {}
        )

        iocs = result.get(
            "iocs",
            {}
        )

        threat_intelligence = result.get(
            "threat_intelligence",
            []
        )

        try:

            score = int(
                analysis.get(
                    "score",
                    0,
                )
            )

        except (
            TypeError,
            ValueError,
        ):

            score = 0

        query = """
            INSERT INTO phishing_investigations (
                investigation_id,
                filename,
                sender,
                reply_to,
                recipient,
                subject,
                phishing_score,
                verdict,
                reasons,
                iocs,
                threat_intelligence
            )
            VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s
            )
            RETURNING id
        """

        cursor.execute(
            query,
            (
                investigation_id,
                filename,
                headers.get("from"),
                headers.get("reply_to"),
                headers.get("to"),
                headers.get("subject"),
                score,
                analysis.get(
                    "verdict",
                    "UNKNOWN",
                ),
                Json(
                    analysis.get(
                        "reasons",
                        [],
                    )
                ),
                Json(iocs),
                Json(threat_intelligence),
            ),
        )

        record_id = cursor.fetchone()[0]

        connection.commit()

        cursor.close()

        return {
            "id": record_id,
            "investigation_id": investigation_id,
            "filename": filename,
            "verdict": analysis.get(
                "verdict",
                "UNKNOWN",
            ),
            "score": score,
        }

    except Exception:

        connection.rollback()

        raise

    finally:

        connection.close()
