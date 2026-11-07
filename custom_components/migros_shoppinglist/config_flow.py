"""Config flow for the Migros Shopping List integration."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.helpers.selector import (
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .api import (
    MigrosAuthError,
    MigrosClient,
    MigrosError,
    create_session,
    create_ssl_context,
)
from .const import CONF_TOTP_SECRET, DOMAIN, LOGGER

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_EMAIL): TextSelector(
            TextSelectorConfig(
                type=TextSelectorType.EMAIL,
                autocomplete="email",
            ),
        ),
        vol.Required(CONF_PASSWORD): TextSelector(
            TextSelectorConfig(
                type=TextSelectorType.PASSWORD,
                autocomplete="current-password",
            ),
        ),
        vol.Required(CONF_TOTP_SECRET): TextSelector(
            TextSelectorConfig(type=TextSelectorType.PASSWORD),
        ),
    }
)


class MigrosConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Migros Shopping List."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}
        if user_input is not None:
            errors = await self._validate_input(user_input)
            if not errors:
                await self.async_set_unique_id(user_input[CONF_EMAIL].lower())
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=user_input[CONF_EMAIL], data=user_input
                )

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        """Handle re-authentication after the stored session expired."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Confirm re-authentication."""
        errors: dict[str, str] = {}
        reauth_entry = self._get_reauth_entry()

        if user_input is not None:
            data = {**reauth_entry.data, **user_input}
            errors = await self._validate_input(data)
            if not errors:
                await self.async_set_unique_id(data[CONF_EMAIL].lower())
                self._abort_if_unique_id_mismatch()
                return self.async_update_reload_and_abort(reauth_entry, data=data)

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=self.add_suggested_values_to_schema(
                STEP_USER_DATA_SCHEMA,
                {CONF_EMAIL: reauth_entry.data[CONF_EMAIL]},
            ),
            description_placeholders={"email": reauth_entry.data[CONF_EMAIL]},
            errors=errors,
        )

    async def _validate_input(self, user_input: Mapping[str, Any]) -> dict[str, str]:
        """Attempt a full login with the provided credentials."""
        ssl_context = await self.hass.async_add_executor_job(create_ssl_context)
        session = create_session(ssl_context)
        client = MigrosClient(
            session,
            email=user_input[CONF_EMAIL],
            password=user_input[CONF_PASSWORD],
            totp_secret=user_input[CONF_TOTP_SECRET],
        )
        try:
            await client.async_login()
        except MigrosAuthError:
            return {"base": "invalid_auth"}
        except MigrosError:
            return {"base": "cannot_connect"}
        except Exception:  # noqa: BLE001
            LOGGER.exception("Unexpected error validating Migros credentials")
            return {"base": "unknown"}
        finally:
            await session.close()
        return {}
