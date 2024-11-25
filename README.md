[![Go Report Card](https://goreportcard.com/badge/github.com/pamelia/gorp)](https://goreportcard.com/report/github.com/pamelia/gorp)
# Go Reverse Proxy
A simple reverse proxy written in Go.


## Listener
- HTTP/2
- TLS 1.3
- TLS client certificate verification

## Backends
- HTTP/HTTPS
- Round-robin load balancing
- TLS server certificate verification (optional)
- Provide CA certificate for TLS server certificate verification (optional)
