"""Todo platform for the Migros Shopping List integration."""

from __future__ import annotations

from homeassistant.components.todo import (
    TodoItem,
    TodoItemStatus,
    TodoListEntity,
    TodoListEntityFeature,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .api import MigrosError, item_display_name, iter_items
from .const import DOMAIN
from .coordinator import (
    MigrosConfigEntry,
    MigrosDataUpdateCoordinator,
    MigrosListData,
)

PARALLEL_UPDATES = 1


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: MigrosConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up Migros shopping lists as todo entities."""
    coordinator = config_entry.runtime_data
    lists_added: set[int] = set()

    @callback
    def add_entities() -> None:
        nonlocal lists_added
        new_lists = set(coordinator.data) - lists_added
        if new_lists:
            async_add_entities(
                MigrosTodoListEntity(coordinator, list_id) for list_id in new_lists
            )
            lists_added |= new_lists

    config_entry.async_on_unload(coordinator.async_add_listener(add_entities))
    add_entities()


class MigrosTodoListEntity(
    CoordinatorEntity[MigrosDataUpdateCoordinator], TodoListEntity
):
    """A Migros shopping list exposed as a To-do list."""

    _attr_has_entity_name = True
    _attr_name = None
    _attr_supported_features = (
        TodoListEntityFeature.CREATE_TODO_ITEM
        | TodoListEntityFeature.UPDATE_TODO_ITEM
        | TodoListEntityFeature.DELETE_TODO_ITEM
    )

    def __init__(
        self, coordinator: MigrosDataUpdateCoordinator, list_id: int
    ) -> None:
        super().__init__(coordinator)
        self._list_id = list_id
        entry_id = coordinator.config_entry.entry_id
        self._attr_unique_id = f"{entry_id}_{list_id}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, self._attr_unique_id)},
            entry_type=DeviceEntryType.SERVICE,
            manufacturer="Migros",
            name=self._list_data.name if self._list_data else f"List {list_id}",
        )

    @property
    def _list_data(self) -> MigrosListData | None:
        return self.coordinator.data.get(self._list_id)

    @property
    def available(self) -> bool:
        return super().available and self._list_data is not None

    @property
    def todo_items(self) -> list[TodoItem] | None:
        data = self._list_data
        if data is None:
            return None
        return [
            TodoItem(
                uid=str(item.get("id")),
                summary=item_display_name(item),
                status=TodoItemStatus.NEEDS_ACTION,
            )
            for _category_id, item in iter_items(data.basket)
        ]

    async def async_create_todo_item(self, item: TodoItem) -> None:
        """Add a free-text item to the shopping list."""
        try:
            await self.coordinator.client.add_custom_item(
                self._list_id, item.summary or ""
            )
        except MigrosError as err:
            raise HomeAssistantError(
                f"Failed to add '{item.summary}' to the Migros list: {err}"
            ) from err
        await self.coordinator.async_request_refresh()

    async def async_update_todo_item(self, item: TodoItem) -> None:
        """Update an item: completing it removes it, otherwise rename it."""
        try:
            if item.status == TodoItemStatus.COMPLETED:
                await self.coordinator.client.remove_item(self._list_id, item.uid)
            else:
                await self.coordinator.client.rename_item(
                    self._list_id, item.uid, item.summary or ""
                )
        except MigrosError as err:
            raise HomeAssistantError(
                f"Failed to update the Migros list item: {err}"
            ) from err
        await self.coordinator.async_request_refresh()

    async def async_delete_todo_items(self, uids: list[str]) -> None:
        """Remove items from the shopping list."""
        try:
            for uid in uids:
                await self.coordinator.client.remove_item(self._list_id, uid)
        except MigrosError as err:
            raise HomeAssistantError(
                f"Failed to remove the Migros list item: {err}"
            ) from err
        await self.coordinator.async_request_refresh()
