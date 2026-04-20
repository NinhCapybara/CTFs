FROM debian:latest

RUN apt-get update -y \
    && apt-get install -y socat \
    && apt-get clean -y

RUN useradd -d /home/challenge -m -s /bin/bash challenge

WORKDIR /home/challenge

COPY flag.txt .
COPY vuln .

RUN chmod +x vuln

USER challenge

CMD ["socat", "tcp-listen:40000,reuseaddr,fork", "exec:./vuln"]
EXPOSE 40000
