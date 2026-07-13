FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/mercutio ./cmd/mercutio

FROM alpine:3.22
RUN adduser -D -u 10001 mercutio
WORKDIR /app
COPY --from=build /out/mercutio /app/mercutio
COPY public /app/public
USER 10001
EXPOSE 9011
ENTRYPOINT ["/app/mercutio"]
