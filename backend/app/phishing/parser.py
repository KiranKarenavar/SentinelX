from email import policy
from email.parser import BytesParser
from email.message import Message
from typing import Any, Dict


def parse_email(raw_email: bytes) -> Dict[str, Any]:
    """
    Parse a raw .eml email.
    """

    message = BytesParser(
        policy=policy.default
    ).parsebytes(raw_email)

    headers = {
        "from": message.get("From"),
        "to": message.get("To"),
        "cc": message.get("Cc"),
        "reply_to": message.get("Reply-To"),
        "subject": message.get("Subject"),
        "date": message.get("Date"),
        "message_id": message.get("Message-ID"),
    }

    body_parts = []

    if message.is_multipart():

        for part in message.walk():

            content_type = part.get_content_type()

            if content_type in (
                "text/plain",
                "text/html",
            ):

                try:
                    body_parts.append(
                        part.get_content()
                    )
                except Exception:
                    pass

    else:

        try:
            body_parts.append(
                message.get_content()
            )
        except Exception:
            pass

    return {
        "headers": headers,
        "body": "\n".join(body_parts),
    }
