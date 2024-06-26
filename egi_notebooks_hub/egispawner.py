"""A Spawner for the EGI Notebooks service
"""

import base64
import uuid

from kubernetes.client import V1ObjectMeta, V1Secret
from kubernetes.client.rest import ApiException
from kubespawner import KubeSpawner
from traitlets import Unicode


class EGISpawner(KubeSpawner):
    token_secret_name_template = Unicode(
        "access-token-{userid}",
        config=True,
        help="""
        Template to use to form the name of secret to store user's token.
        `{username}` is expanded to the escaped, dns-label safe username.
        This must be unique within the namespace the pvc are being spawned
        in, so if you are running multiple jupyterhubs spawning in the
        same namespace, consider setting this to be something more unique.
        """,
    )

    token_secret_volume_name_template = Unicode(
        "secret-{userid}",
        config=True,
        help="""
        Template to use to form the name of secret to store user's token.
        `{username}` is expanded to the escaped, dns-label safe username.
        This must be unique within the namespace the pvc are being spawned
        in, so if you are running multiple jupyterhubs spawning in the
        same namespace, consider setting this to be something more unique.
        """,
    )

    token_mount_path = Unicode(
        "/var/run/secrets/egi.eu/",
        config=True,
        help="""
        Path where the token secret will be mounted.
        """,
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pvc_name = uuid.uuid4().hex
        self.token_secret_name = self._expand_user_properties(
            self.token_secret_name_template
        )
        token_secret_volume_name = self._expand_user_properties(
            self.token_secret_volume_name_template
        )
        self.volumes.append(
            {
                "name": token_secret_volume_name,
                "secret": {"secretName": self.token_secret_name},
            }
        )
        self.volume_mounts.append(
            {
                "name": token_secret_volume_name,
                "mountPath": self.token_mount_path,
                "readOnly": True,
            }
        )
        self._create_token_secret()

    def get_pvc_manifest(self):
        """Tries to fix volumes of to avoid issues with too long user names"""
        pvcs = self.api.list_namespaced_persistent_volume_claim(
            namespace=self.namespace
        )
        for pvc in pvcs.items:
            if (
                pvc.metadata.annotations.get("hub.jupyter.org/username", "")
                == self.user.name
            ):
                self.pvc_name = pvc.metadata.name
                break
        vols = []
        # pylint: disable=access-member-before-definition
        for v in self.volumes:
            claim = v.get("persistentVolumeClaim", {})
            if claim.get("claimName", "").startswith("claim-"):
                v["persistentVolumeClaim"]["claimName"] = self.pvc_name
            vols.append(v)
        self.volumes = vols
        return super().get_pvc_manifest()

    # overriding this one to avoid long usernames as labels
    def _build_common_labels(self, extra_labels):
        labels = super()._build_common_labels(extra_labels)
        del labels["hub.jupyter.org/username"]
        return labels

    def _get_secret_manifest(self, data):
        """creates a secret in k8s that will contain the token of the user"""
        meta = V1ObjectMeta(
            name=self.token_secret_name,
            labels=self._build_common_labels({}),
            annotations=self._build_common_annotations({}),
        )
        secret = V1Secret(metadata=meta, type="Opaque", data=data)
        return secret

    def _create_token_secret(self):
        secret = self._get_secret_manifest({})
        try:
            self.api.create_namespaced_secret(namespace=self.namespace, body=secret)
            self.log.info("Created access token secret %s", self.token_secret_name)
        except ApiException as e:
            if e.status == 409:
                self.log.info("Secret %s exists, not creating", self.token_secret_name)
            else:
                raise

    def _update_token_secret(self, data):
        secret = self._get_secret_manifest(data)
        try:
            self.api.patch_namespaced_secret(
                name=self.token_secret_name, namespace=self.namespace, body=secret
            )
        except ApiException:
            raise

    def set_access_token(self, access_token, id_token=None):
        """updates the secret in k8s with the token of the user"""
        data = {
            "access_token": base64.b64encode(access_token.encode()).decode(),
            "id_token": None,
        }
        if id_token:
            data["id_token"] = base64.b64encode(id_token.encode()).decode()
        self._update_token_secret(data)
