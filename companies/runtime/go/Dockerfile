# Go services of the test companies (companies/*/company.yaml with language: go).
# Standard library only, so the build needs no module downloads.
# Contains none of the ATG platform's code.
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/service .

FROM alpine:3.20
COPY --from=build /out/service /app/service
USER 10001
ENTRYPOINT ["/app/service"]
