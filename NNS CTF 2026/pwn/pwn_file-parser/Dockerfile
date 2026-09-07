FROM python:3.12-slim-bookworm@sha256:4427763a1ba36f5aa8f656a03e5d00f3b8d61f5dd950c73df6c14f8c7640f8ab

RUN apt-get update \
    && apt-get install -y --no-install-recommends socat \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -M -s /usr/sbin/nologin ctf

WORKDIR /app
COPY --chmod=555 fileparser .
COPY --chmod=444 wrapper.py .

USER ctf
EXPOSE 1337
CMD ["socat", "-dd", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:'python3 /app/wrapper.py',pty,stderr,setsid,sigint,sane"]
