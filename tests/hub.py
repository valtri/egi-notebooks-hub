"""
Module for emulation of the JupyterHub API parts that are used by the authenticator.
"""

import asyncio
import logging
import os
import re
import socket
import threading
import urllib.parse

import pytest
import pytest_asyncio
import requests

DEFAULT_LISTEN_HOST: str = "127.0.0.1"
DEFAULT_LISTEN_PORT: str = "8500"


@pytest.fixture(scope="session")
def hub_listen_address() -> str:
    """
    Fixture to get listen address for OAuth callback.
    """
    return os.getenv("LISTEN_ADDRESS", f"{DEFAULT_LISTEN_HOST}:{DEFAULT_LISTEN_PORT}")


class DummyHandler:
    """
    Minimal stub of ``tornado.web.RequestHandler``.

    JupyterHub only calls ``handler.get_argument(name, default)`` inside
    ``authenticate``.
    """

    def __init__(self, args: dict):
        self._args = args

    def get_argument(self, name, default=None):
        # Mimic Tornado’s behaviour of raising a ``MissingArgumentError`` only
        # when default is ``None`` – but for our tests returning ``None`` is fine
        return self._args.get(name, default)

    # For the auth‑code flow some authenticators also read cookies
    def get_secure_cookie(self, name):
        # In tests we just return the value we stored in ``args`` under the same key
        return self.args.get(name)


@pytest.fixture
def dummy_handler():
    """Factory that creates a ``DummyHandler`` from a dict of POST arguments."""

    def _factory(args: dict):
        return DummyHandler(args)

    return _factory


class DummyUser:
    """
    ``User`` mock – JupyterHub calls ``await user.get_auth_state()``.

    The method returns the dict we pass at construction time.
    """

    def __init__(self, name: str, auth_state: dict | None = None):
        self.name = name
        self._auth_state = auth_state

    async def get_auth_state(self):
        return self._auth_state


@pytest.fixture
def dummy_user():
    """Factory returning a ``DummyUser`` instance."""

    def _factory(name: str, auth_state: dict | None = None):
        return DummyUser(name, auth_state)

    return _factory


class DummySpawner:
    """A fake spawner that only stores the environment dict."""

    def __init__(self):
        self.environment = {}


@pytest.fixture
def dummy_spawner():
    return DummySpawner()


def first_line(content: str) -> str:
    """
    Get the first line of the HTML response.

    :param content:
    The string content.
    """
    return re.match(r"^(.*?)(\n|$)", content).group(1)


@pytest_asyncio.fixture(scope="function")
async def event_loop(event_loop_policy):
    """
    Fixture providing event loop for async operations.

    Separated fixture for it due to initial problems to make it work, possible
    portability issues.

    :param event_loop_policy:
    Fixture from pytest asyncio.
    """
    return event_loop_policy.get_event_loop()


@pytest_asyncio.fixture
async def oauth_callback_server(
    pytestconfig: pytest.Config,
    hub_listen_address: str,
    keycloak_client_callback_url: str,
    event_loop,
) -> tuple[str, str]:
    """
    Starts a tiny HTTP server on specified listen address that records the query
    string of the first GET request it receives (the OAuth redirect) and then
    shuts down.

    The fixture returns a tuple ``(callback_url, future)`` where ``callback_url`` is
    the full URL the authenticator must use as its redirect URI and ``future`` is an
    ``asyncio.Future`` that resolves to a dict ``{'code': ..., 'state': ...}``.

    :param pytestconfig:
    Pytest configuration object.

    :param hub_listen_address:
    OAuth callback server listen address "host:port".

    :param keycloak_client_callback_url:
    OAuth client callback URL, which must corresponds with ``hub_lisen_address``.
    """
    host: str
    port_s: str
    host, port_s = hub_listen_address.split(":", 2)
    port: int = int(port_s)

    # Prepare a future that the test will await
    result_fut: asyncio.Future[dict] = event_loop.create_future()

    # Request handler
    class CallbackHandler:

        def __init__(self, conn, addr):
            self.conn = conn
            self.addr = addr
            self.handle()
            logging.debug(f"Callback: connection from {self.addr}")

        def handle(self) -> None:
            data = self.conn.recv(4096).decode("utf-8")
            logging.info(f"Callback: received {first_line(data)}")
            logging.debug(data)
            # Very tiny HTTP parser – we only need the first line
            request_line = data.split("\r\n")[0]
            method, path, _ = request_line.split()
            if method != "GET":
                self._write("HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                return

            # Extract the query part of the URL
            parsed = urllib.parse.urlsplit(path)
            query = urllib.parse.parse_qs(parsed.query)
            # ``code`` and ``state`` are single‑value strings
            result = {
                "code": query.get("code", [None])[0],
                "state": query.get("state", [None])[0],
            }
            # Resolve the future (only once)
            if not result_fut.done():
                event_loop.call_soon_threadsafe(result_fut.set_result, result)

            # Respond with a tiny HTML page to see something
            body = """<!DOCTYPE html>
<html lang=\"en\">
    <head>
        <title>OAuth Test Callback</title>
        <meta charset="UTF-8">
    </head>
    <body>Login successful – you may close this window.</body>
</html>
"""
            self._write(
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                f"Content-Length: {len(body) + 2}\r\n\r\n"
                f"{body}"
            )
            self.conn.close()

        def _write(self, data: str):
            logging.info(f"Callback: sending {first_line(data)}")
            logging.debug(data)
            self.conn.sendall(data.encode("utf-8"))

    #  Server thread – runs a blocking `accept()` loop
    def server_thread():
        with socket.socket() as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            logging.info(f"Callback: listening at {host}:{port}")
            srv.bind((host, port))
            srv.listen(1)
            # Accept **one** connection, then stop
            conn, addr = srv.accept()
            CallbackHandler(conn, addr)

    thread = threading.Thread(target=server_thread, daemon=True)
    thread.start()

    # Return the URL the authenticator should use as redirect_uri and the future
    callback_url: str = f"http://{host}:{port}"
    yield callback_url, result_fut

    # Clean‑up – the thread will exit after handling the single request
    thread.join(timeout=1)
    logging.debug("Callback: shutdown")


def run_oauth_code_flow(
    *,
    auth_endpoint: str,
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    username: str,
    password: str,
    redirect_uri: str,
    session: requests.Session | None = None,
) -> dict:
    """
    Executes a full OAuth 2.0 Authorization‑Code flow against a real Keycloak
    server and returns the *raw* token response (access, refresh, id_token).

    :param auth_endpoint:
        URL of the Keycloak ``/protocol/openid-connect/auth`` endpoint.
    :param token_endpoint:
        URL of the ``/protocol/openid-connect/token`` endpoint (used for the
        final exchange of ``code`` → tokens).
    :paream client_id:
        Client credentials ID.
    :param client_secret:
        Client credentials secret.
    :param username:
        Test user credentials name.
    :param password:
        Test user credentials password.
    :param redirect_uri:
        URL where Keycloak will redirect back (must be reachable by the test).
    :param session:
        Optional ``requests.Session``; a new one will be created if omitted.

    Returns
    -------
    dict
        The JSON payload returned by the token endpoint.
    """
    sess = session or requests.Session()
    sess.verify = True

    #
    # Build the authorization request URL.
    #
    # We generate a *known* ``state`` value so we can later assert that the
    # authenticator checked it.
    #
    state = "test-state-12345"
    auth_params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid email profile",
        "state": state,
    }
    auth_url = f"{auth_endpoint}?{urllib.parse.urlencode(auth_params)}"

    # GET the auth URL – Keycloak will redirect to the login page
    r = sess.get(auth_url, allow_redirects=True)
    r.raise_for_status()

    #
    # POST the login form.
    #
    # The login page rendered by Keycloak has the fields ``username`` and ``password``
    # (plus a hidden ``kc_idp_hint`` that we can ignore).  We locate the form’s action
    # URL by parsing the HTML; however, for the default theme the action URL is the
    # same as the GET URL, so we can simply reuse ``auth_url``.
    #
    login_data = {
        "username": username,
        "password": password,
        "credentialId": "",  # needed for some themes, safe to send empty
    }
    # The login POST must follow redirects because Keycloak will finally
    # redirect back to ``redirect_uri``
    login_resp = sess.post(r.url, data=login_data, allow_redirects=True)
    login_resp.raise_for_status()

    # At this point the session has been redirected to ``redirect_uri`` **with**
    # ``code`` and ``state`` query parameters.  Grab them from the final URL.
    final_url = login_resp.url
    parsed = urllib.parse.urlsplit(final_url)
    query = urllib.parse.parse_qs(parsed.query)

    code = query.get("code", [None])[0]
    returned_state = query.get("state", [None])[0]

    if not code or returned_state != state:
        raise RuntimeError(
            f"OAuth flow did not return a valid code. "
            f"code={code!r} state={returned_state!r}"
        )

    # Exchange the code for tokens
    token_payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "client_secret": client_secret,
    }
    token_resp = sess.post(token_endpoint, data=token_payload)
    token_resp.raise_for_status()
    return token_resp.json()
