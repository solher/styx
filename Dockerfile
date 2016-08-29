FROM alpine:latest

ADD https://raw.githubusercontent.com/solher/env2flags/master/env2flags.sh /usr/local/bin/env2flags
RUN chmod u+x /usr/local/bin/env2flags

COPY ./styx /usr/local/bin

WORKDIR /

EXPOSE 8082
ENTRYPOINT ["env2flags", "--"]
CMD ["styx"]