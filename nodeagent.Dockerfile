FROM golang:1.26-alpine AS build
WORKDIR /src
COPY nodeagent/go.mod nodeagent/go.sum ./
RUN go mod download
COPY nodeagent/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/mercutio-nodeagent ./cmd/mercutio-nodeagent

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=build /out/mercutio-nodeagent /usr/local/bin/mercutio-nodeagent
COPY nodeagent/dist/mercutio.cap.json nodeagent/dist/mercutio.cap.json.sig nodeagent/dist/mercutio.bpf.o /usr/share/mercutio/programs/
USER 0
EXPOSE 9090
ENTRYPOINT ["/usr/local/bin/mercutio-nodeagent"]
