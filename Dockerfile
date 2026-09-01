# Starting with the image used in helm jupyterhub
FROM quay.io/jupyterhub/k8s-hub:4.4.1

USER root

# Do installation in 2 phases to cache dependendencies
COPY requirements.txt /egi-notebooks-hub/
RUN pip3 install --no-cache-dir -r /egi-notebooks-hub/requirements.txt

# Now install the code itself
COPY . /egi-notebooks-hub/
# hadolint ignore=DL3013
RUN pip3 install --no-cache-dir /egi-notebooks-hub

# Copy images to the right place so they are found
RUN cp -r /egi-notebooks-hub/static/* /usr/local/share/jupyterhub/static/

# Install OIDC token to Kerberos ticket converter
ARG KRB5_OIDC2CC_VERSION=1.1.0
ARG KRB5_OIDC2CC_CHECKSUM=d876d54789905e931769022ed9da754c759f5c4bf487285b0b431604c3fe167e
ARG KRB5_OIDC2CC_PLATFORM=dpkg%3A%20%5Bdebian%3A12%5D
RUN set -eux \
 && curl -fSL --retry 3 --max-time 30 --connect-timeout 10 \
    -o url.txt \
    "https://gitlab.cesnet.cz/702/projekty/krb5-oidc2cc/-/jobs/artifacts/$KRB5_OIDC2CC_VERSION/raw/url.txt?job=${KRB5_OIDC2CC_PLATFORM}" \
 && curl -fSL --retry 3 --max-time 30 --connect-timeout 10 \
    -o python3-krb5cc.deb \
    "$(cat url.txt | head -n 1)" \
 && echo "$KRB5_OIDC2CC_CHECKSUM python3-krb5cc.deb" | sha256sum -c - \
 && apt-get update \
 && apt-get install --no-install-recommends -y ./python3-krb5cc.deb \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f url.txt python3-krb5cc.deb \
 && krb5-oidc2cc --help >/dev/null

HEALTHCHECK --interval=5m --timeout=3s \
  CMD curl -f http://localhost:8000/hub/health || exit 1

ARG NB_USER=jovyan
USER ${NB_USER}
