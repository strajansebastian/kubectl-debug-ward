# used for development

FROM ubuntu:22.04

RUN mkdir -p /app /config
WORKDIR /app

RUN apt update && \
    apt install -y golang && \
    rm -rf /var/lib/apt/lists/*

COPY cmd pkg go.mod go.sum /app/

RUN apt update && \
    apt install -y vim && \
    rm -rf /var/lib/apt/lists/*

