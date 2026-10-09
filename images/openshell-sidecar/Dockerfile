# The ArtzAIn sidecar for an NVIDIA OpenShell gateway (`artzain openshell
# sidecar`), as an image for the gateway shapes that run in containers.
#
# What is in it, and nothing else:
#   * the base image below, named by its digest;
#   * the `artzain` wheel as PyPI serves it, named by its SHA-256
#     (artzain.lock);
#   * what `artzain[openshell]` needs from other projects, each wheel named by
#     its SHA-256 (requirements.lock).
# Nothing is compiled, and nothing is fetched that a lock does not name.
#
# How it runs:
#   * as uid 10001, never root, with no shell account and no home;
#   * on a read-only root filesystem. The sidecar writes only where it is
#     told to (the gRPC socket, the state file, the journal, the base policy
#     copy). /run/artzain and /var/lib/artzain are there for that, owned by
#     the sidecar's user, so a volume mounted on either starts out writable
#     by it and by nobody else;
#   * listening on loopback only (127.0.0.1:8088), plus the Unix socket the
#     gateway calls when OPENSHELL_SIDECAR_GRPC names one.
#
# Two ways to build, chosen by ARTZAIN_SOURCE:
#   pypi   (releases) the wheel artzain.lock names, checked against its hash;
#   wheel  (rehearsals) a wheel built from this repository's python/ tree and
#          put in wheels/, so a change can be tried before it is published.
# ARTZAIN_VERSION is required either way, and the build fails unless that is
# the version that got installed.
#
# To move the base image: `docker buildx imagetools inspect
# public.ecr.aws/docker/library/python:3.12-slim-bookworm` prints the digest
# of the multi-platform index (the ECR Public mirror of the Docker official
# image: same manifest and digest as Docker Hub, whose anonymous pull limit
# stops builds on shared CI runners). The Python here and in
# scripts/lock_openshell_sidecar_image.py (engine repository) are the same
# one; a test holds them together.
ARG PYTHON_IMAGE=public.ecr.aws/docker/library/python:3.12-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3

FROM ${PYTHON_IMAGE} AS build
ARG ARTZAIN_SOURCE=pypi
ARG ARTZAIN_VERSION
COPY requirements.lock artzain.lock /lock/
COPY wheels/ /wheels/
RUN set -eu; \
    test -n "${ARTZAIN_VERSION}" || { echo "ARTZAIN_VERSION is required" >&2; exit 1; }; \
    python -m venv /opt/artzain; \
    pip="/opt/artzain/bin/pip --no-cache-dir --disable-pip-version-check"; \
    $pip install --require-hashes --only-binary=:all: -r /lock/requirements.lock; \
    case "${ARTZAIN_SOURCE}" in \
      pypi) $pip install --no-deps --require-hashes --only-binary=:all: -r /lock/artzain.lock ;; \
      wheel) $pip install --no-deps --no-index /wheels/artzain-"${ARTZAIN_VERSION}"-py3-none-any.whl ;; \
      *) echo "ARTZAIN_SOURCE must be pypi or wheel" >&2; exit 1 ;; \
    esac; \
    installed="$(/opt/artzain/bin/python -c 'import artzain; print(artzain.__version__)' 2>/dev/null || true)"; \
    test "${installed}" = "${ARTZAIN_VERSION}" || { \
      echo "installed artzain ${installed:-none}, expected ${ARTZAIN_VERSION}" >&2; exit 1; }; \
    $pip check; \
    /opt/artzain/bin/python -m compileall -q /opt/artzain/lib; \
    /opt/artzain/bin/python -m pip uninstall --yes --quiet pip

FROM ${PYTHON_IMAGE}
ARG ARTZAIN_VERSION
LABEL org.opencontainers.image.title="ArtzAIn OpenShell sidecar" \
      org.opencontainers.image.description="Decides an NVIDIA OpenShell gateway's governed writes with the ArtzAIn engine" \
      org.opencontainers.image.source="https://github.com/CogNEXUSlabs/cognexus-tools" \
      org.opencontainers.image.vendor="CogNEXUS Labs" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${ARTZAIN_VERSION}"
# The base image's own pip is not needed at run time, and is not left behind.
RUN set -eu; \
    python -m pip uninstall --yes --quiet pip; \
    groupadd --system --gid 10001 artzain; \
    useradd --system --uid 10001 --gid 10001 --home-dir /nonexistent --no-create-home \
        --shell /usr/sbin/nologin artzain; \
    install -d -o 10001 -g 10001 -m 0700 /run/artzain /var/lib/artzain
COPY --from=build /opt/artzain /opt/artzain
ENV PATH="/opt/artzain/bin:${PATH}" \
    HOME=/nonexistent \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OPENSHELL_SIDECAR_HOST=127.0.0.1 \
    OPENSHELL_SIDECAR_PORT=8088
USER 10001:10001
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % (os.environ.get('OPENSHELL_SIDECAR_PORT') or '8088'), timeout=2)"]
ENTRYPOINT ["artzain", "openshell", "sidecar"]
