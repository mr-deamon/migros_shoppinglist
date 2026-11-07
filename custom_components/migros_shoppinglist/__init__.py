"""The Migros Shopping List integration."""

from __future__ import annotations

from homeassistant.const import CONF_EMAIL, CONF_PASSWORD, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from .api import MigrosClient, create_session, create_ssl_context
from .const import CONF_TOTP_SECRET, DOMAIN, STORAGE_VERSION
from .coordinator import MigrosConfigEntry, MigrosDataUpdateCoordinator

PLATFORMS: list[Platform] = [Platform.TODO]


async def async_setup_entry(hass: HomeAssistant, entry: MigrosConfigEntry) -> bool:
    """Set up Migros Shopping List from a config entry."""
    store: Store = Store(hass, STORAGE_VERSION, f"{DOMAIN}.{entry.entry_id}")
    session_data = await store.async_load()

    ssl_context = await hass.async_add_executor_job(create_ssl_context)
    websession = create_session(ssl_context)

    client = MigrosClient(
        websession,
        session_data=session_data,
        email=entry.data[CONF_EMAIL],
        password=entry.data[CONF_PASSWORD],
        totp_secret=entry.data.get(CONF_TOTP_SECRET),
    )

    coordinator = MigrosDataUpdateCoordinator(hass, entry, client, store)
    coordinator.websession = websession

    try:
        await coordinator.async_config_entry_first_refresh()
    except Exception:
        await websession.close()
        raise

    entry.runtime_data = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: MigrosConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        await entry.runtime_data.websession.close()
    return unload_ok
