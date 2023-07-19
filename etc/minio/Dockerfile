# Purpose:
#   When configured for oauth/OIDC, minio doesn't seem to retry connection attempts to IDP

# Reference:
#   https://github.com/minio/minio/issues/11604#issuecomment-786284078      :   minio: allow providing init scripts; Feb 2021
#   https://hub.docker.com/r/minio/minio/dockerfile/                        :   original minio Dockerfile
#   https://docs.docker.com/compose/startup-order/                          :   suggestion for waiting until dependencies are "ready"

# Instructions:
#   podman build --rm -t quay.io/redhat_naps_da/minio:0.0.1 etc/minio


FROM docker.io/minio/mc:RELEASE.2023-07-11T23-30-44Z as client

FROM docker.io/minio/minio:RELEASE.2023-07-11T21-29-34Z.fips

ADD wait-for-it.sh /usr/bin

# kube lifecycle events like postStart hook can't use a seperate image
COPY --from=client /usr/bin/mc /usr/bin/mc

# mc requires writable configuration directory
RUN mkdir /bin/.mc && chmod ugo+rw /bin/.mc
