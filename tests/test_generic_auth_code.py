import asyncio
import logging
import os

import pytest
from oauthenticator.generic import GenericOAuthenticator
from . import hub


@pytest.fixture
def oauth2_endpoints(pytestconfig: pytest.Config, keycloak_admin):
    """
    Return the two endpoint URLs used by Keycloak for the *standard* flow.
    """
    base = pytestconfig.base_url
    realm = pytestconfig.realm
    # XXX
    auth_endpoint = f"{base}/realms/{realm}/protocol/openid-connect/auth"
    token_endpoint = f"{base}/realms/{realm}/protocol/openid-connect/token"
    return auth_endpoint, token_endpoint


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

    # Start the tiny callback HTTP server that will receive the redirect
    redirect_uri, code_future = oauth_callback_server

    # Run the *real* OAuth flow *outside* the authenticator
    auth_endpoint, token_endpoint = oauth2_endpoints
    token_response = hub.run_oauth_code_flow(
        auth_endpoint=auth_endpoint,
        token_endpoint=token_endpoint,
        client_id=client_id,
        client_secret=client_secret,
        username=username,
        password=password,
        redirect_uri=redirect_uri,
    )
    # ``token_response`` contains the tokens we will later compare against
    # Keep it for later assertions
    assert "access_token" in token_response
    assert "refresh_token" in token_response

    # At this point the tiny callback server has already received the
    # redirect and stored ``code`` & ``state`` in the future.
    callback_params = await asyncio.wait_for(code_future, timeout=5)
    code = callback_params["code"]
    state = callback_params["state"]
    assert code is not None and state == "test-state-12345"

    # A dummy Tornado request handler that mimics what JupyterHub
    # gives to ``authenticate``.  The only arguments we need are
    # ``code`` and ``state`` – everything else is irrelevant for the hook.
    class DummyHandler:

        def __init__(self, data):
            self._data = data

        def get_argument(self, name, default=None):
            return self._data.get(name, default)

        # The authenticator may also read the `state` cookie (some implementations
        # store it there).  For this test we simply return the value we already
        # have in the query string.
        def get_secure_cookie(self, name):
            if name == "oauth_state":
                return state.encode()
            return None

    handler = DummyHandler({"code": code, "state": state})

    # Call the authenticator *asynchronous* method
    result = await auth.authenticate(handler)

    # Assertions – they are identical to the password‑grant test,
    # except that the username now comes from the token / id_token.
    assert result is not None, "authenticate() should succeed with a valid code"
    # The algorithm inside the authenticator (userinfo call or id_token decode)
    # should have produced the same username we used to log in.
    assert result["name"] == username

    auth_state = result["auth_state"]
    # Tokens from the authenticator must match the ones we retrieved via the
    # *external* flow (they are the raw values returned by the token endpoint).
    assert auth_state["access_token"] == token_response["access_token"]
    assert auth_state["refresh_token"] == token_response["refresh_token"]
    assert auth_state["id_token"] == token_response.get("id_token")

    # Optional sanity: the full token response is stored as well.
    assert auth_state["token_response"] == token_response


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
