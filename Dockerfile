FROM golang:1.22-alpine as builder

WORKDIR /src
COPY go.sum go.sum
COPY go.mod go.mod
COPY main.go main.go

RUN go mod download
RUN go build -o expired-cert-notify .

FROM alpine:3
WORKDIR /app
COPY --from=builder /src/expired-cert-notify /app/expired-cert-notify
CMD ["/app/expired-cert-notify"]
