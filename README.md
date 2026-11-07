# Migros Shopping List (Home Assistant)

Custom Home Assistant integration for Migros shopping lists.

## Authentication and TOTP

Migros login for this integration uses:

- Email
- Password
- TOTP secret (base32 secret from your authenticator setup)

The integration performs a full login flow and generates the current 6-digit TOTP code from your stored TOTP secret during authentication.  
For this integration, the TOTP secret is treated as required during setup and re-authentication.

How to find your TOTP secret:

- Use the base32 secret shown when enabling MFA/TOTP in your Migros account.
- If you only have a QR code in another app, export or reveal the underlying base32 secret from that app.

## Repository layout

- `custom_components/migros_shoppinglist/` — integration source

## Local install (manual)

1. Copy `custom_components/migros_shoppinglist` into your Home Assistant config directory under `custom_components/`.
2. Restart Home Assistant.
3. Add **Migros Shopping List** via **Settings -> Devices & Services -> Add Integration**.
