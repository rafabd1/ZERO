FROM golang:1.24-alpine AS build

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN go build -trimpath -ldflags="-s -w" -o /out/zero ./cmd/zero

FROM alpine:3.21

RUN apk add --no-cache ca-certificates bind-tools git && \
    adduser -D -h /home/zero zero

COPY --from=build /out/zero /usr/local/bin/zero

USER zero
WORKDIR /home/zero

ENTRYPOINT ["zero"]
CMD ["worker"]
