import logging
from keycloak import KeycloakAdmin, KeycloakOpenID


def test_setup(
    keycloak_admin: KeycloakAdmin,
    keycloak_client: tuple[str, str],
    keycloak_openid: KeycloakOpenID,
    keycloak_user: dict[str, str],
) -> None:
    """
    Check the infrastructure before testing.
    """
    logging.info(f"admin: {keycloak_admin.connection.username}")

    realm: str = keycloak_admin.get_current_realm()
    realm_detail: dict[str, object] = keycloak_admin.get_realm(realm)
    logging.info(f"realm: {realm_detail['realm']}")

    scopes = keycloak_admin.get_client_scopes()
    logging.info(f"scopes: {[s.get('name') for s in scopes]}")

    roles = keycloak_admin.get_realm_roles()
    logging.info(f"roles: {[r.get('name', None) for r in roles]}")

    logging.info(f"client: {keycloak_client[0]}")

    logging.info(f"user: {keycloak_user['username']} ({keycloak_user['user_id']})")

    logging.info(
        f"openid instance: {keycloak_openid.client_id} @ {keycloak_openid.realm_name}, "
        f"URL {keycloak_openid.well_known().get('issuer', None)}"
    )

    token: dict[str, object] = keycloak_openid.token(
        username=keycloak_user["username"],
        password=keycloak_user["password"],
        grant_type="client_credentials",
        scope="openid",
    )
    token_info: dict[str, object] = {}
    for item in token.items():
        if item[0].endswith("token"):
            token_info[item[0]] = (
                None if item[1] is None else f"(length {len(item[1])})"
            )
        else:
            token_info[item[0]] = item[1]
    logging.info(f"got token: {token_info}")
