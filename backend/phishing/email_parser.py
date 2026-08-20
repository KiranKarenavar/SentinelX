from email import policy
from email.parser import BytesParser
from typing import Any


class EmailParser:
    """
    Parse .eml email files and extract useful email information.
    """

    def parse(self, file_bytes: bytes) -> dict[str, Any]:
        message = BytesParser(
            policy=policy.default
        ).parsebytes(file_bytes)

        headers = {}

        for key, value in message.items():
            headers[key] = str(value)

        body_parts = []
        attachments = []

        if message.is_multipart():

            for part in message.walk():

                content_type = part.get_content_type()
                content_disposition = (
                    part.get_content_disposition()
                )

                if content_disposition == "attachment":

                    filename = part.get_filename()

                    attachments.append({
                        "filename": filename,
                        "content_type": content_type,
                        "size": len(
                            part.get_payload(decode=True)
                            or b""
                        ),
                    })

                elif content_type in (
                    "text/plain",
                    "text/html",
                ):

                    try:
                        content = part.get_content()

                        body_parts.append({
                            "content_type": content_type,
                            "content": content,
                        })

                    except Exception:
                        continue

        else:

            try:
                body_parts.append({
                    "content_type": message.get_content_type(),
                    "content": message.get_content(),
                })
            except Exception:
                pass

        return {
            "headers": headers,
            "body_parts": body_parts,
            "attachments": attachments,
        }
