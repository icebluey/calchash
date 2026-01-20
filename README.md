# calchash
```
# linux
CGO_ENABLED=0 GOARCH=amd64 GOAMD64=v3 go build -trimpath -ldflags "-s -w" -mod=mod -o calchash calchash.go
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -mod=mod -o calchash calchash.go

# windows
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 GOAMD64=v3 go build -trimpath -ldflags "-s -w" -mod=mod -o calchash.exe calchash.go
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -mod=mod -o calchash.exe calchash.go
```
