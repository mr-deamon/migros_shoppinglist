"""Constants for the Migros Shopping List integration."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Final

DOMAIN: Final = "migros_shoppinglist"

LOGGER = logging.getLogger(__package__)

CONF_TOTP_SECRET: Final = "totp_secret"

SCAN_INTERVAL: Final = timedelta(seconds=90)

STORAGE_VERSION: Final = 1
