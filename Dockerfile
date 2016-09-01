FROM alpine:latest

RUN mkdir -p /app && touch /app/config.yml
COPY ./styx /usr/local/bin

WORKDIR /

ENV CONFIG_FILE=/app/config.yml
EXPOSE 3000 8082
ENTRYPOINT ["styx"]