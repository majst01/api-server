FROM openpolicyagent/opa:latest-static as opa
FROM golang:1.22-alpine as builder

RUN apk add \
    binutils \
    gcc \
    git \
    libc-dev \
    make

WORKDIR /work
COPY --from=opa /opa /usr/local/bin/opa
COPY . .
RUN make

FROM alpine:3.20
RUN apk add ca-certificates
COPY --from=builder /work/bin/server /
ENTRYPOINT [ "/server" ]