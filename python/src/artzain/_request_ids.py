"""The correlation id an event carries to the dashboard."""

from __future__ import annotations

import re
import uuid
from typing import Optional

_DECISION_ID = re.compile(r"[0-9A-HJKMNP-TV-Z]{26}")


def correlation_id(request_id: Optional[str]) -> str:
    """The id to send for *request_id*, or a new one when it is empty.

    A decision id (26 characters, as ``decide()`` returns it) is sent in upper
    case, the form the server stores, so the event's token counts land on
    that decision. Any other id is sent in lower case.
    """
    given = (request_id or "").strip()
    if not given:
        return uuid.uuid4().hex
    upper = given.upper()
    if _DECISION_ID.fullmatch(upper):
        return upper
    return given.lower()
