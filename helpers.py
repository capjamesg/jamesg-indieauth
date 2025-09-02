import time
from typing import Optional

import indieweb_utils

from config import ME


def verify_code(client_id: str, redirect_uri: str, decoded_code: str) -> Optional[str]:
    if (
        int(time.time()) > decoded_code["expires"]
        or redirect_uri != decoded_code["redirect_uri"]
        or client_id != decoded_code["client_id"]
    ):
        return "invalid_grant"

    return None


def is_authenticated_as_allowed_user(me_url: str) -> bool:
    """
    Check if the allowed user has a valid rel=me link pointing to their domain.
    """
    home_me_links = indieweb_utils.get_valid_relmeauth_links(
        ME, require_rel_me_link_back=False
    )

    for link in home_me_links:
        if link == me_url:
            return True

    return False
