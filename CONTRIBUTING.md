# Contributing

Use Go 1.25 and keep runtime code standard-library-only. Network behavior must remain bounded and cancellation-aware. Run:

```sh
gofmt -w .
go vet ./...
go test ./...
go test -race ./...
go build ./cmd/certpulse
```
