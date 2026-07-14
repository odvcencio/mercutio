FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/mercutio ./cmd/mercutio
RUN GOBIN=/out go install m31labs.dev/buckley/cmd/buckley@a31f35464db133e01d240296e6a4f1e2fb5a871d

FROM alpine:3.22
RUN apk add --no-cache ca-certificates git && adduser -D -u 10001 mercutio
WORKDIR /app
COPY --from=build /out/mercutio /app/mercutio
COPY --from=build /out/buckley /usr/local/bin/buckley
COPY public /app/public
USER 10001
EXPOSE 9011
ENTRYPOINT ["/app/mercutio"]
