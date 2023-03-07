FROM golang:1.20 as build

WORKDIR /src
COPY . .
RUN go mod init github.com/liamg/antispam-action
RUN go build -v -o /app ./cmd/action

FROM gcr.io/distroless/base
COPY --from=build /app /app
CMD ["/app"]
