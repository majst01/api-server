FROM openpolicyagent/opa:latest-static as opa
FROM golang:1.23-alpine as builder

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

FROM gcr.io/distroless-debian12:nonroot
COPY --from=builder /work/bin/server /
ENTRYPOINT [ "/server" ]