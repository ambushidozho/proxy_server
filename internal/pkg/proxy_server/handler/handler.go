package delivery

import (
	"bufio"
	"crypto/tls"

	//"proxy/internal/models"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"proxy/internal/models"
	"proxy/internal/pkg/lib"
	"proxy/internal/pkg/proxy_server"
	"strings"
)

type StartServer struct {
	repo proxy.RepoProxy
	port string
}

func NewProxyServer(ProxyRepo proxy.RepoProxy, port string) *StartServer {
	return &StartServer{repo: ProxyRepo, port: port}
}

func (ps *StartServer) ListenAndServe() error {
	server := http.Server{
		Addr: ps.port,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				ps.proxyHTTPS(w, r)
			} else {
				ps.proxyHTTP(w, r)
			}
		}),
	}
	return server.ListenAndServe()
}

func (ps *StartServer) proxyHTTP(w http.ResponseWriter, r *http.Request) {
	r.Header.Del("Proxy-Connection")

	reqId, err := ps.repo.SaveRequest(r)
	if err != nil {
		log.Printf("error while	saving request: %v", err)
	}

	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	resp.Cookies()
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	_, err = ps.repo.SaveResponse(reqId, resp)
	if err != nil {
		log.Printf("error while saving response: %v", err)
	}

	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (ps *StartServer) proxyHTTPS(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking is not supported in your request", http.StatusInternalServerError)
		return
	}

	localConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}

	_, err = localConn.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		localConn.Close()
		return
	}
	defer localConn.Close()

	host := strings.Split(r.Host, ":")[0]

	tlsConfig, err := lib.GenerateTLSConfig(host, r.URL.Scheme)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tlsLocalConn := tls.Server(localConn, &tlsConfig)
	err = tlsLocalConn.Handshake()
	if err != nil {
		tlsLocalConn.Close()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer tlsLocalConn.Close()

	remoteConn, err := tls.Dial("tcp", r.URL.Host, &tlsConfig)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer remoteConn.Close()

	reader := bufio.NewReader(tlsLocalConn)
	request, err := http.ReadRequest(reader)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	requestByte, err := httputil.DumpRequest(request, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, err = remoteConn.Write(requestByte)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	serverReader := bufio.NewReader(remoteConn)
	response, err := http.ReadResponse(serverReader, request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rawResponse, err := httputil.DumpResponse(response, true)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = tlsLocalConn.Write(rawResponse)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	request.URL.Scheme = "https"
	hostAndPort := strings.Split(r.URL.Host, ":")
	request.URL.Host = hostAndPort[0]

	reqId, err := ps.repo.SaveRequest(request)
	if err != nil {
		log.Printf("error while saving request:  %v", err)
	}

	_, err = ps.repo.SaveResponse(reqId, response)
	if err != nil {
		log.Printf("error while saving response:  %v", err)
	}
}

func (ps *StartServer) Proxy(r *http.Request) models.Response {
	r.Header.Del("Proxy-Connection")

	reqId, err := ps.repo.SaveRequest(r)
	if err != nil {
		log.Printf("error while saving request: %v", err)
	}

	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		return models.Response{}
	}
	defer resp.Body.Close()

	response, err := ps.repo.SaveResponse(reqId, resp)
	if err != nil {
		log.Printf("error while saving response: %v", err)
	}
	return response
}
