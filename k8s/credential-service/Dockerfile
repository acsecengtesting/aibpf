FROM golang:1.21-alpine AS build
WORKDIR /src
COPY main.go .
COPY go.mod .
RUN go mod tidy && CGO_ENABLED=0 go build -o /credential-service .

FROM alpine:3.19
COPY --from=build /credential-service /usr/local/bin/credential-service
ENTRYPOINT ["/usr/local/bin/credential-service"]
