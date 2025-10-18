FROM golang:1.24 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/authz ./cmd/authz

FROM gcr.io/distroless/base-debian12
WORKDIR /
COPY --from=build /out/authz /authz
COPY --from=build /src/policies /policies
ENTRYPOINT ["/authz"]
