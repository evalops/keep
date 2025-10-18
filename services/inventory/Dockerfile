FROM golang:1.22 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/inventory ./services/inventory/server

FROM gcr.io/distroless/base-debian12
COPY --from=build /out/inventory /inventory
ENTRYPOINT ["/inventory"]
