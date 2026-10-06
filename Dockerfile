FROM golang:1.27.1-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY checker ./checker
COPY labs ./labs
COPY internal ./internal
COPY cmd ./cmd
RUN CGO_ENABLED=0 go test ./... && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/checker ./cmd/checker

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/checker /usr/local/bin/checker
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/checker"]
