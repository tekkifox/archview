FROM golang:1.23-alpine AS build

WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN go build -o /out/archview ./cmd/archview

FROM alpine:3.20

RUN addgroup -S archview && adduser -S archview -G archview
WORKDIR /app
COPY --from=build /out/archview /app/archview
USER archview
EXPOSE 8080
ENTRYPOINT ["/app/archview"]