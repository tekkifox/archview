FROM golang:1.27-alpine AS build

WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
COPY docs ./docs
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/archview ./cmd/archview

FROM alpine:3.24

RUN addgroup -S archview && adduser -S archview -G archview
WORKDIR /app
COPY --from=build /out/archview /app/archview
USER archview
EXPOSE 8080
ENTRYPOINT ["/app/archview"]
