package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/pamelia/gorp/pkg/config"
	"github.com/pamelia/gorp/pkg/logger"
	"github.com/pamelia/gorp/pkg/pki"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

func Start(configPath string) {
	sugar := logger.Logger.Sugar()
	sugar.Info("Starting the server")
	sugar.Infof("Loading config from %s", configPath)

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	for _, listenCfg := range cfg.Listens {
		// Start each listener in a separate goroutine
		go func(lc config.ListenConfig) {
			if err := startListener(lc); err != nil {
				log.Fatalf("Failed to start listener on %s:%d: %v", lc.Address, lc.Port, err)
			}
		}(listenCfg)
	}

	// Block forever
	select {}
}

// startListener sets up and starts a TLS server with mutual authentication
func startListener(listenCfg config.ListenConfig) error {
	sugar := logger.Logger.Sugar()
	sugar.Infof("Starting listener on %s:%d", listenCfg.Address, listenCfg.Port)

	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair(listenCfg.TLSCert, listenCfg.TLSKey)
	if err != nil {
		return fmt.Errorf("failed to load server cert/key: %w", err)
	}

	// Load CA certificate to verify client certificates
	caCert, err := os.ReadFile(listenCfg.TLSCACert)
	if err != nil {
		return fmt.Errorf("failed to read CA cert: %w", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to append CA cert")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	// Prepare the reverse proxy with round-robin load balancing
	proxy := newReverseProxy(listenCfg.Backends)

	server := &http.Server{
		Handler:      proxy,
		TLSConfig:    tlsConfig,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  90 * time.Second,
	}

	addr := net.JoinHostPort(listenCfg.Address, strconv.Itoa(listenCfg.Port))
	listener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	sugar.Infof("Server listening on %s", addr)
	return server.Serve(listener)
}

// Define the bufferPool type
type bufferPool struct {
	pool *sync.Pool
}

func (bp *bufferPool) Get() []byte {
	b := bp.pool.Get()
	if b == nil {
		return make([]byte, 32*1024) // Adjust size as needed
	}
	return b.([]byte)
}

func (bp *bufferPool) Put(b []byte) {
	bp.pool.Put(b)
}

// newReverseProxy creates a reverse proxy that forwards requests to backends in a round-robin fashion
func newReverseProxy(backends []config.BackendConfig) *httputil.ReverseProxy {
	sugar := logger.Logger.Sugar()
	var counter uint32
	backendCount := uint32(len(backends))

	// Prepare maps for backend configurations and transports
	backendMap := make(map[string]config.BackendConfig)
	transportMap := make(map[string]*http.Transport)

	// Prepare the transports for each backend
	for _, backend := range backends {
		hostPort := net.JoinHostPort(backend.Address, strconv.Itoa(backend.Port))
		backendMap[hostPort] = backend

		// Prepare the transport with appropriate TLS settings
		tr := &http.Transport{
			MaxIdleConnsPerHost:   100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ForceAttemptHTTP2:     true,
		}

		if backend.Scheme == "https" {
			tlsConfig := &tls.Config{}

			// Reuse TLS sessions
			tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(128)

			if backend.SkipVerifyTLSCert {
				tlsConfig.InsecureSkipVerify = true
			} else {
				tlsConfig.InsecureSkipVerify = false
			}

			if backend.TLSCACert != "" {
				sugar.Infof("Loading CA cert from %s", backend.TLSCACert)
				caCertPool, err := pki.GetCACertPool(backend.TLSCACert)
				if err != nil {
					log.Fatalf("Failed to get CA cert pool: %v", err)
				}
				tlsConfig.RootCAs = caCertPool
			}

			tr.TLSClientConfig = tlsConfig
		}

		transportMap[hostPort] = tr
	}

	director := func(req *http.Request) {
		// Select backend using atomic counter for thread safety
		idx := atomic.AddUint32(&counter, 1)
		backend := backends[idx%backendCount]

		// Update the request to point to the selected backend
		req.URL.Scheme = backend.Scheme
		req.URL.Host = net.JoinHostPort(backend.Address, strconv.Itoa(backend.Port))
		// Update the Host header if necessary
		req.Host = req.URL.Host

		sugar.Infof("Proxying request for %s to %s://%s %s %s", req.RemoteAddr, req.URL.Scheme, req.URL.Host,
			req.Method, req.RequestURI)

	}

	transport := &BackendTransport{
		TransportMap: transportMap,
	}

	// Initialize the buffer pool
	bufferPool := &bufferPool{
		pool: &sync.Pool{
			New: func() interface{} {
				return make([]byte, 32*1024)
			},
		},
	}

	proxy := &httputil.ReverseProxy{
		Director:   director,
		Transport:  transport,
		BufferPool: bufferPool,
	}

	return proxy
}

// BackendTransport implements http.RoundTripper and allows per-backend transport configurations
type BackendTransport struct {
	TransportMap map[string]*http.Transport
}

func (t *BackendTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Get the backend host from req.URL.Host
	backendHost := req.URL.Host

	// Get the transport for this backend
	transport, ok := t.TransportMap[backendHost]
	if !ok {
		// Fallback to default transport
		transport = http.DefaultTransport.(*http.Transport)
	}

	// Use the transport to make the request
	return transport.RoundTrip(req)
}
