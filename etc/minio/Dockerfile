# https://hub.docker.com/r/minio/minio/dockerfile/                  :   original minio Dockerfil
# https://docs.docker.com/compose/startup-order/                    :   suggestion for waiting until dependencies are "ready"

# podman build --rm -t quay.io/jbride/minio:0.0.1 etc/minio

FROM docker.io/minio/minio:RELEASE.2022-09-17T00-09-45Z.fips

ADD wait-for-it.sh /usr/bin

ENTRYPOINT ["/usr/bin/wait-for-it.sh"]
