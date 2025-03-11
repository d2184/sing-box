package hysteria2_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/provider/parser"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

const (
	sniExtensionID        uint16 = 0x0000
	chromeTrustAnchorsExt uint16 = 0xca34
)

type testCertBundle struct {
	tlsCert stdtls.Certificate
	rootPEM string
}

func newHysteria2TestChain(t *testing.T, dnsNames []string, ips []net.IP) testCertBundle {
	t.Helper()
	now := time.Now()
	var (
		parent    *x509.Certificate
		parentKey *ecdsa.PrivateKey
		leafKey   *ecdsa.PrivateKey
		chain     []*x509.Certificate
	)
	names := []string{"hy2-test-root", "hy2-test-intermediate", "hy2-test-leaf"}
	for i, name := range names {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(i + 1)),
			Subject:               pkix.Name{CommonName: name},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(time.Hour),
			BasicConstraintsValid: true,
			IsCA:                  i < 2,
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		if tmpl.IsCA {
			tmpl.KeyUsage |= x509.KeyUsageCertSign
		} else {
			tmpl.DNSNames = dnsNames
			tmpl.IPAddresses = ips
		}
		if parent == nil {
			parent, parentKey = tmpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		chain = append([]*x509.Certificate{cert}, chain...)
		parent, parentKey, leafKey = cert, key, key
	}

	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain[2].Raw})
	return testCertBundle{
		tlsCert: stdtls.Certificate{
			Certificate: [][]byte{chain[0].Raw, chain[1].Raw, chain[2].Raw},
			PrivateKey:  leafKey,
			Leaf:        chain[0],
		},
		rootPEM: string(rootPEM),
	}
}

type observedHello struct {
	serverName string
	extensions []uint16
}

type observedAuth struct {
	host       string
	path       string
	auth       string
	negotiated string
}

type hysteria2TestServer struct {
	port      int
	helloCh   <-chan observedHello
	authCh    <-chan observedAuth
	authCount *atomic.Int32
}

func startHysteria2TestServer(t *testing.T, cert stdtls.Certificate, password string) hysteria2TestServer {
	t.Helper()
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)

	helloCh := make(chan observedHello, 8)
	authCh := make(chan observedAuth, 8)
	var authCount atomic.Int32

	serverTLS := &stdtls.Config{
		Certificates: []stdtls.Certificate{cert},
		NextProtos:   []string{http3.NextProtoH3},
		GetConfigForClient: func(chi *stdtls.ClientHelloInfo) (*stdtls.Config, error) {
			select {
			case helloCh <- observedHello{
				serverName: chi.ServerName,
				extensions: slices.Clone(chi.Extensions),
			}:
			default:
			}
			return nil, nil
		},
	}
	tr := &quic.Transport{Conn: udpConn}
	tr.SetSingleUse(true)
	ln, err := tr.ListenEarly(serverTLS, &quic.Config{
		EnableDatagrams:      true,
		HandshakeIdleTimeout: 5 * time.Second,
	})
	if err != nil {
		_ = tr.Close()
		_ = udpConn.Close()
		require.NoError(t, err)
	}

	h3Server := &http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authCount.Add(1)
			negotiated := ""
			if r.TLS != nil {
				negotiated = r.TLS.NegotiatedProtocol
			}
			select {
			case authCh <- observedAuth{
				host:       r.Host,
				path:       r.URL.Path,
				auth:       r.Header.Get("Hysteria-Auth"),
				negotiated: negotiated,
			}:
			default:
			}
			if r.Method != http.MethodPost || r.URL.Path != "/auth" || r.Header.Get("Hysteria-Auth") != password {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.Header().Set("Hysteria-UDP", "true")
			w.Header().Set("Hysteria-CC-RX", "auto")
			w.WriteHeader(233)
		}),
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		_ = h3Server.ServeListener(ln)
	})
	t.Cleanup(func() {
		_ = h3Server.Close()
		_ = ln.Close()
		_ = tr.Close()
		_ = udpConn.Close()
		wg.Wait()
	})
	return hysteria2TestServer{
		port:      udpConn.LocalAddr().(*net.UDPAddr).Port,
		helloCh:   helloCh,
		authCh:    authCh,
		authCount: &authCount,
	}
}

func parseHysteria2LinkOptions(t *testing.T, link string) option.Hysteria2OutboundOptions {
	t.Helper()
	outbound, err := parser.ParseSubscriptionLink(link)
	require.NoError(t, err)
	options, ok := outbound.Options.(*option.Hysteria2OutboundOptions)
	require.True(t, ok)
	return *options
}

func dialHysteria2Handshake(t *testing.T, options option.Hysteria2OutboundOptions) error {
	t.Helper()
	nopLogger := log.NewNOPFactory().Logger()
	outbound, err := hysteria2.NewOutbound(t.Context(), nil, nopLogger, "hy2-test", options)
	require.NoError(t, err)

	scope := adapter.NewScope(t.Context(), nopLogger)
	require.NoError(t, outbound.(*hysteria2.Outbound).Start(adapter.StartStateInitialize, scope))
	defer func() {
		_ = scope.Close()
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	packetConn, err := outbound.ListenPacket(ctx, M.Socksaddr{})
	if err == nil {
		_ = packetConn.Close()
	}
	return err
}

func readHello(t *testing.T, ch <-chan observedHello) observedHello {
	t.Helper()
	select {
	case hello := <-ch:
		return hello
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for ClientHello")
		return observedHello{}
	}
}

func readAuth(t *testing.T, ch <-chan observedAuth) observedAuth {
	t.Helper()
	select {
	case auth := <-ch:
		return auth
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for HTTP/3 auth request")
		return observedAuth{}
	}
}

func TestHysteria2ExplicitSNIHandshake(t *testing.T) {
	const password = "secret-password"
	dnsBundle := newHysteria2TestChain(t, []string{"cert.example"}, nil)

	t.Run("ChromeParrot", func(t *testing.T) {
		srv := startHysteria2TestServer(t, dnsBundle.tlsCert, password)
		opts := parseHysteria2LinkOptions(t, fmt.Sprintf("hy2://%s@127.0.0.1:%d?sni=cert.example", password, srv.port))
		opts.TLS.Certificate = []string{dnsBundle.rootPEM}

		require.NoError(t, dialHysteria2Handshake(t, opts))
		hello := readHello(t, srv.helloCh)
		require.Equal(t, "cert.example", hello.serverName)
		require.Contains(t, hello.extensions, sniExtensionID)
		require.Contains(t, hello.extensions, chromeTrustAnchorsExt)

		auth := readAuth(t, srv.authCh)
		require.Equal(t, "hysteria", auth.host)
		require.Equal(t, http3.NextProtoH3, auth.negotiated)
		require.Equal(t, int32(1), srv.authCount.Load())
	})

	t.Run("standard QUIC", func(t *testing.T) {
		srv := startHysteria2TestServer(t, dnsBundle.tlsCert, password)
		opts := parseHysteria2LinkOptions(t, fmt.Sprintf("hy2://%s@127.0.0.1:%d?sni=cert.example", password, srv.port))
		opts.TLS.Certificate = []string{dnsBundle.rootPEM}
		opts.DisableChromeParrot = true

		require.NoError(t, dialHysteria2Handshake(t, opts))
		hello := readHello(t, srv.helloCh)
		require.Equal(t, "cert.example", hello.serverName)
		require.Contains(t, hello.extensions, sniExtensionID)
		require.NotContains(t, hello.extensions, chromeTrustAnchorsExt)

		auth := readAuth(t, srv.authCh)
		require.Equal(t, "hysteria", auth.host)
		require.Equal(t, http3.NextProtoH3, auth.negotiated)
	})
}
