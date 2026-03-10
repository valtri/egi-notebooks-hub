import asyncio
import json
import logging
import os

import pytest
from oauthenticator.generic import GenericOAuthenticator

from . import hub


@pytest.fixture
def oauth2_endpoints(pytestconfig: pytest.Config) -> tuple[str, str, str]:
    """
    Return the two endpoint URLs used by Keycloak for the *standard* flow.

    :param pytestconfig:
    Pytest configuration object.
    """
    base = pytestconfig.base_url
    realm = pytestconfig.realm
    # XXX
    auth_endpoint = f"{base}/realms/{realm}/protocol/openid-connect/auth"
    token_endpoint = f"{base}/realms/{realm}/protocol/openid-connect/token"
    userinfo_endpoint = f"{base}/realms/{realm}/protocol/openid-connect/userinfo"
    return auth_endpoint, token_endpoint, userinfo_endpoint


@pytest.mark.asyncio
async def test_authorization_code_flow(
    pytestconfig,
    keycloak_admin,
    keycloak_client,
    keycloak_user,
    oauth_callback_server,
    oauth2_endpoints,
):
    """
    End‑to‑end test that:

    1. Performs a *real* auth‑code login against Keycloak.
    2. Captures the ``code`` from the callback server.
    3. Calls ``GenericOAuthenticator.authenticate`` with a handler that
       contains the ``code`` and the originally generated ``state``.
    4. Asserts that the authenticator returns the expected JupyterHub user dict.

    :param pytestconfig:
    Pytest configuration object.
    """
    client_id, client_secret = keycloak_client
    username = keycloak_user["username"]
    password = keycloak_user["password"]

    # Build the authenticator – we will *override* the internal
    auth = GenericOAuthenticator()
    auth.server_url = pytestconfig.base_url
    auth.realm_name = pytestconfig.realm
    auth.client_id = client_id
    auth.client_secret = client_secret
    auth.verify = True
    auth.enable_pkce = True
    # available in default Keycloak setup
    auth.username_claim = "preferred_username"

    # Start the tiny callback HTTP server that will receive the redirect
    redirect_uri, code_future = oauth_callback_server

    # Run the *real* OAuth flow *outside* the authenticator
    auth_endpoint, token_endpoint, userinfo_endpoint = oauth2_endpoints

    # Set our redirect URL in authentcator
    auth.oauth_callback_url = redirect_uri
    auth.userdata_url = userinfo_endpoint
    auth.token_url = token_endpoint

    code_verifier: str = hub.code_verifier_gen()
    code_challenge: str = hub.pkce_encode(code_verifier)
    pkce_params: dict[str, str] = {
        "code_challenge_method": "S256",
        "code_challenge": code_challenge,
    }
    response_params = hub.launch_oauth_code_flow(
        auth_endpoint=auth_endpoint,
        token_endpoint=token_endpoint,
        client_id=client_id,
        client_secret=client_secret,
        username=username,
        password=password,
        redirect_uri=redirect_uri,
        params=pkce_params,
    )
    logging.debug(f"Launch OAuth code flow parameters: {response_params}")

    # At this point the tiny callback server has already received the
    # redirect and stored ``code`` & ``state`` in the future.
    callback_params = await asyncio.wait_for(code_future, timeout=5)
    code = callback_params["code"]
    state = callback_params["state"]
    logging.info(f"Authentication code and state from callback: {code}, {state}")
    logging.debug(f"All params from callback: {callback_params}")
    assert code is not None and state == "test-state-12345"

    handler = hub.DummyHandler(
        data={"code": code, "state": state, },
        state_cookie={
            "code_verifier": code_verifier,
        },
    )

    # Call the authenticator *asynchronous* method
    result = await auth.authenticate(handler)

    # Assertions – they are identical to the password‑grant test,
    # except that the username now comes from the token / id_token.
    assert result is not None, "authenticate() should succeed with a valid code"
    # The algorithm inside the authenticator (userinfo call or id_token decode)
    # should have produced the same username we used to log in.
    assert result["name"] == username

    auth_state = result["auth_state"]
    logging.debug(f"auth_state = {json.dumps(auth_state, indent=4)}")
    assert auth_state["access_token"] is not None, "access_token returned"
    assert auth_state["id_token"] is not None, "id_token returned"
    assert auth_state["refresh_token"] is not None, "refresh_token returned"


@pytest.mark.asyncio
@pytest.mark.skipif("TEST_OAUTH_SERVER" not in os.environ, reason="Debugging purposes")
async def test_oauth_server(oauth_callback_server):
    """
    Launch OAuth server to snuggle and poke manually.

    Example of launch:

    ``TEST_OAUTH_SERVER=1 pytest -v --log-cli-level=DEBUG -ktest_oauth_server``

    :param oauth_callback_server:
    OAuth server to play with.
    """
    redirect_uri, code_future = oauth_callback_server
    callback_params = await asyncio.wait_for(code_future, timeout=None)
    code = callback_params["code"]
    state = callback_params["state"]
    logging.info(f"OAuth server: URI {code}, code {state}")
