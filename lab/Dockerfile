FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends dovecot-imapd dovecot-pop3d postfix openssl tcpdump python3 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY run.py /lab/run.py
ENTRYPOINT ["python3", "/lab/run.py"]
