FROM golang:alpine AS base

WORKDIR /go/src/github.com/mikesmitty/mdns-mesh
COPY . .
RUN go get -d -v ./...
RUN go install -a -v -trimpath -tags netgo -ldflags '-extldflags "-static"' ./...


FROM alpine:3.23

RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=base /go/bin/mdns-mesh .

CMD /app/mdns-mesh
