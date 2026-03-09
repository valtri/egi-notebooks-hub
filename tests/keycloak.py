"""
Module for testing with real Keycloak server providing OIDC.
"""

import json
import logging
import os
import secrets
import string
import time

import pytest
import requests
from pathlib import Path
from urllib.parse import urljoin
from keycloak import KeycloakAdmin, KeycloakOpenID
from keycloak.exceptions import KeycloakGetError


def pytest_configure(config: pytest.Config) -> None:
    """
    Configuration for tests.

    :param config:
    Pytest configuration object.
    """
    config.base_url: str = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
    config.realm: str = os.getenv("KEYCLOAK_REALM", "test-realm")
    config.client_callbacks: list[str] = os.getenv(
        "KEYCLOAK_CLIENT_CALLBACKS", ""
    ).split(",")
    scopes_file = (
        Path(__file__)
        .relative_to(Path.cwd())
        .parent.joinpath("config")
        .joinpath("scopes.json")
    )
    logging.debug("Loading scopes from {scopes_file}")
    with open(scopes_file, "r") as f:
        config.scopes = json.load(f)
    logging.debug("=> {len(config.scopes)} scopes")


@pytest.fixture(scope="session")
def keycloak_client_callback_url(pytestconfig: pytest.Config) -> str:
    """
    Fixture to get the callback URL.

    :param pytestconfig:
    Pytest configuration object.
    """
    assert (
        pytestconfig.client_callbacks is not None
    ), "KEYCLOAK_CLIENT_CALLBACKS required"
    assert len(pytestconfig.client_callbacks) > 0, "KEYCLOAK_CLIENT_CALLBACKS required"
    return pytestconfig.client_callbacks[0]


def _wait_for_keycloak(base_url: str, realm: str, timeout: int = 90) -> None:
    """
    Wait until the /realms/<realm> endpoint answers.
    """
    health_url = urljoin(base_url, f"/realms/{realm}")
    deadline = time.time() + timeout
    logging.debug(f"Connecting to {health_url}")
    while time.time() < deadline:
        try:
            r = requests.get(health_url, timeout=2)
            if r.status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.5)
    raise RuntimeError(f"Keycloak {realm} not healthy after {timeout}s")


def _ensure_realm(
    keycloak_admin: KeycloakAdmin, realm: str, scopes: dict[str, object]
) -> None:
    """
    Create the realm if doesn't exist.
    """
    exists: bool = False
    try:
        keycloak_admin.get_realm(realm)
        exists = True
        logging.debug(f"Found realm {realm}")
    except KeycloakGetError:
        pass
    if not exists:
        logging.info(f"Creating realm {realm}")
        payload = {
            "id": f"{realm}",
            "realm": f"{realm}",
            "displayName": "Testing Realm",
            "clientScopes": scopes,
            "enabled": True,
        }
        keycloak_admin.import_realm(payload=payload)


def _randkey(length: int = 20):
    """
    Generate random string for using as credentials.
    """
    avail_chars = string.ascii_letters + string.digits + string.punctuation
    return "".join(secrets.choice(avail_chars) for i in range(20))


@pytest.fixture(scope="session")
def keycloak_admin(pytestconfig: pytest.Config) -> KeycloakAdmin:
    """
    Fixture that yields a *ready* Keycloak admin client.
    It is ensured that the testing realm is created and admin is switched to it.
    """
    admin_user: str = os.getenv("KEYCLOAK_ADMIN", "admin")
    admin_pass: str = os.getenv("KEYCLOAK_ADMIN_PASSWORD", "")
    realm: str = pytestconfig.realm

    # Wait for the service to be up (use the admin /realms endpoint)
    _wait_for_keycloak(pytestconfig.base_url, "master")

    kc_admin: KeycloakAdmin = KeycloakAdmin(
        server_url=pytestconfig.base_url,
        username=admin_user,
        password=admin_pass,
        realm_name="master",
        verify=True,
    )

    _ensure_realm(kc_admin, realm, pytestconfig.scopes)

    logging.debug(f"Switching realm for keycloak_admin to {realm}")
    kc_admin.change_current_realm(realm)

    return kc_admin


@pytest.fixture(scope="session")
def keycloak_client(
    pytestconfig: pytest.Config, keycloak_admin: KeycloakAdmin
) -> tuple[str, str]:
    """
    Fixture that ensures the OIDC client exists.
    """
    client_id: str = os.getenv("KEYCLOAK_CLIENT_ID")
    client_secret: str = os.getenv("KEYCLOAK_CLIENT_SECRET")
    external: bool = False
    if client_id:
        external = True
    else:
        client_id = f"client-{int(time.time()*1000)}"
    if not client_secret:
        client_secret = _randkey()

    ident: str
    try:
        ident = keycloak_admin.get_client_id(client_id)
    except KeycloakGetError:
        payload: dict[object] = {
            "id": client_id,
            "clientId": client_id,
            "secret": client_secret,
            "enabled": True,
            "directAccessGrantsEnabled": True,
            "serviceAccountsEnabled": True,
            "standardFlowEnabled": True,
            "redirectUris": pytestconfig.client_callbacks,
            "webOrigins": ["*"],
            "defaultClientScopes": [
                "openid",
                "profile",
                "email",
            ],
            "optionalClientScopes": [
                "offline_access",
                "entitlements",
                "eduperson_entitlement",
            ],
        }
        logging.info(f"Creating OpenID client {client_id}")
        ident = keycloak_admin.create_client(payload, skip_exists=True)
    else:
        logging.debug(f"Found OpenId client {client_id} ({ident})")

    yield (client_id, client_secret)

    # Clean‑up
    if not external:
        try:
            logging.info(f"Deleting client {client_id} ({ident})")
            keycloak_admin.delete_client(client_id)
        except Exception as exc:  # pragma: no cover
            logging.error(f"Cleanup user failed: {exc}")
    else:
        logging.debug(f"Kept external user {client_id} ({ident})")


@pytest.fixture
def keycloak_user(keycloak_admin: KeycloakAdmin) -> None:
    """
    Create a temporary user, yield its credentials, and delete it afterwards.
    """
    username: str = os.getenv("KEYCLOAK_USER_NAME")
    password: str = os.getenv("KEYCLOAK_USER_PASSWORD")
    external: bool = False
    if username:
        external = True
    else:
        username = f"user-{int(time.time()*1000)}"
    if not password:
        password = _randkey()

    logging.info(f"Creating user {username} if not exists")
    user_id = keycloak_admin.create_user(
        {
            "username": username,
            "enabled": True,
            "email": f"oauth-test-{username}@xample.com",
            "emailVerified": True,
            "firstName": "Test",
            "lastName": "User",
            "credentials": [
                {"type": "password", "value": password, "temporary": False}
            ],
        },
        exist_ok=True,
    )

    # Assign the default "user" role (optional)
    # role = keycloak_admin.get_realm_role("user")
    # keycloak_admin.assign_realm_roles(user_id=user_id, roles=[role])

    yield {"username": username, "password": password, "user_id": user_id}

    # Clean‑up
    if not external:
        try:
            logging.info(f"Deleting user {username} ({user_id})")
            keycloak_admin.delete_user(user_id)
        except Exception as exc:  # pragma: no cover
            logging.error(f"Cleanup user failed: {exc}")
    else:
        logging.debug(f"Kept external user {username} ({user_id})")


@pytest.fixture
def keycloak_openid(
    pytestconfig: pytest.Config, keycloak_client: tuple[str, str]
) -> KeycloakOpenID:
    """
    Fixture that gives you a **ready OpenID client** (for token fetches)

    :param pytestconfig:
    Pytest configuration object.

    :param keycloak_client:
    Keycload OpenID client (clientId, clientSecret).
    """
    base_url = pytestconfig.base_url
    realm = pytestconfig.realm
    client_id = keycloak_client[0]
    client_secret = keycloak_client[1]

    return KeycloakOpenID(
        server_url=base_url,
        client_id=client_id,
        realm_name=realm,
        client_secret_key=client_secret,
        verify=True,
    )
