package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/pamelia/gorp/pkg/config"
	"github.com/pamelia/gorp/pkg/logger"
	"github.com/pamelia/gorp/pkg/pki"
	"go.uber.org/zap"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func (lrw *loggingResponseWriter) Write(b []byte) (int, error) {
	if lrw.statusCode == 0 {
		lrw.statusCode = http.StatusOK
	}
	n, err := lrw.ResponseWriter.Write(b)
	lrw.size += n
	return n, err
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lrw := &loggingResponseWriter{ResponseWriter: w}

		// Pass the request to the next handler
		next.ServeHTTP(lrw, r)

		// After the handler returns, log the request details
		duration := time.Since(start)

		// Extract client IP address
		clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			clientIP = r.RemoteAddr
		}
		if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
			clientIP = ip
		}

		logger.Logger.Info("HTTP request",
			zap.String("client_ip", clientIP),
			zap.String("method", r.Method),
			zap.String("uri", r.RequestURI),
			zap.String("protocol", r.Proto),
			zap.Int("status", lrw.statusCode),
			zap.Int("size", lrw.size),
			zap.String("user_agent", r.UserAgent()),
			zap.Duration("duration", duration),
		)
	})
}

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

	// Map to store TLS certificates for each virtual host
	tlsCertMap := make(map[string]tls.Certificate)
	for _, vh := range listenCfg.VirtualHosts {
		cert, err := tls.LoadX509KeyPair(vh.TLSCert, vh.TLSKey)
		if err != nil {
			return fmt.Errorf("failed to load cert for %s: %w", vh.Hostname, err)
		}
		sugar.Infof("Certificate for %s loaded, Subject: %s", vh.Hostname, cert.Leaf.Subject)
		tlsCertMap[vh.Hostname] = cert
	}

	// Map to store TLS CA certificates for each virtual host
	caCertPoolMap := make(map[string]*x509.CertPool)
	for _, vh := range listenCfg.VirtualHosts {
		caCertPool, err := pki.GetCACertPool(vh.TLSCACert)
		if err != nil {
			return fmt.Errorf("failed to get CA cert pool for %s: %w", vh.Hostname, err)
		}
		caCertPoolMap[vh.Hostname] = caCertPool
	}

	// Configure TLS with SNI support
	tlsConfig := &tls.Config{
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			return &tls.Config{
				Certificates: []tls.Certificate{tlsCertMap[info.ServerName]},
				ClientCAs:    caCertPoolMap[info.ServerName],
				ClientAuth:   tls.RequireAndVerifyClientCert,
				MinVersion:   tls.VersionTLS13,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				},
			}, nil
		},
	}

	// Create a map of reverse proxies for each virtual host
	proxies := make(map[string]http.Handler)
	for _, vh := range listenCfg.VirtualHosts {
		sugar.Infof("Creating reverse proxy for %s", vh.Hostname)
		proxies[vh.Hostname] = loggingMiddleware(newReverseProxy(vh.Backends))
	}
	sugar.Infof("Reverse proxies created for %d virtual hosts", len(proxies))

	// Create the main HTTP handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if proxy, ok := proxies[host]; ok {
			proxy.ServeHTTP(w, r)
		} else {
			http.Error(w, fmt.Sprintf("No reverse proxy found for %s", r.Host), http.StatusNotFound)
		}
	})

	// Create the HTTP server
	server := &http.Server{
		Handler:      handler,
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

			// Set the DialContext with a custom timeout
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 60 * time.Second,
			}).DialContext,
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
