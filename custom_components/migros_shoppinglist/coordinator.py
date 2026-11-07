"""DataUpdateCoordinator for the Migros Shopping List integration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import aiohttp

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import MigrosAPIError, MigrosAuthError, MigrosClient, MigrosError
from .const import DOMAIN, LOGGER, SCAN_INTERVAL

type MigrosConfigEntry = ConfigEntry[MigrosDataUpdateCoordinator]


@dataclass
class MigrosListData:
    """Data for a single shopping list."""

    info: dict[str, Any]
    basket: dict[str, Any]

    @property
    def list_id(self) -> int:
        return self.info["shoppingListId"]

    @property
    def name(self) -> str:
        return self.info.get("shoppingListName") or f"List {self.list_id}"


class MigrosDataUpdateCoordinator(DataUpdateCoordinator[dict[int, MigrosListData]]):
    """Polls shopping lists and persists the auth session across restarts."""

    config_entry: MigrosConfigEntry
    websession: aiohttp.ClientSession

    def __init__(
        self,
        hass: HomeAssistant,
        config_entry: MigrosConfigEntry,
        client: MigrosClient,
        store: Store,
    ) -> None:
        super().__init__(
            hass,
            LOGGER,
            config_entry=config_entry,
            name=DOMAIN,
            update_interval=SCAN_INTERVAL,
        )
        self.client = client
        self.store = store

    async def _async_persist(self) -> None:
        """Persist the mutable auth session (cookies + JWT)."""
        await self.store.async_save(self.client.data)

    async def _async_update_data(self) -> dict[int, MigrosListData]:
        try:
            lists = await self.client.get_lists()
            result: dict[int, MigrosListData] = {}
            for info in lists:
                list_id = info["shoppingListId"]
                basket = await self.client.get_basket(list_id)
                result[list_id] = MigrosListData(info=info, basket=basket)
        except MigrosAuthError as err:
            raise ConfigEntryAuthFailed(err) from err
        except (MigrosAPIError, MigrosError) as err:
            raise UpdateFailed(err) from err
        finally:
            await self._async_persist()
        return result

    async def _async_setup(self) -> None:
        try:
            await self.client.get_lists()
        except MigrosAuthError as err:
            raise ConfigEntryAuthFailed(err) from err
        except (MigrosAPIError, MigrosError) as err:
            raise ConfigEntryNotReady(err) from err
        finally:
            await self._async_persist()
