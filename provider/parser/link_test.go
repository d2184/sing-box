package parser

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func TestParseVMessLinkSNI(t *testing.T) {
	link := "vmess://" + base64.RawURLEncoding.EncodeToString([]byte(`{"add":"192.0.2.1","port":"443","id":"11111111-1111-1111-1111-111111111111","tls":"tls","sni":"example.com"}`))
	outbound, err := ParseSubscriptionLink(link)
	require.NoError(t, err)

	options := outbound.Options.(*option.VMessOutboundOptions)
	require.Equal(t, "192.0.2.1", options.Server)
	require.Equal(t, "example.com", options.TLS.ServerName)
}

func TestParseVMessLinkURLStyle(t *testing.T) {
	outbound, err := ParseSubscriptionLink("vmess://11111111-1111-1111-1111-111111111111@192.0.2.1:443?type=tcp#test")
	require.NoError(t, err)

	require.Equal(t, "test", outbound.Tag)
	options := outbound.Options.(*option.VMessOutboundOptions)
	require.Equal(t, "192.0.2.1", options.Server)
	require.Equal(t, uint16(443), options.ServerPort)
	require.Equal(t, "11111111-1111-1111-1111-111111111111", options.UUID)
}

func TestParseVMessLinkURLStyleWebsocket(t *testing.T) {
	outbound, err := ParseSubscriptionLink("vmess://11111111-1111-1111-1111-111111111111@192.0.2.1:443?type=ws&host=example.com&path=/ws")
	require.NoError(t, err)

	options := outbound.Options.(*option.VMessOutboundOptions)
	require.NotNil(t, options.Transport)
	require.Equal(t, C.V2RayTransportTypeWebsocket, options.Transport.Type)
	require.Equal(t, "/ws", options.Transport.WebsocketOptions.Path)
}

func TestParseVMessLinkURLStyleGRPC(t *testing.T) {
	outbound, err := ParseSubscriptionLink("vmess://11111111-1111-1111-1111-111111111111@192.0.2.1:443?type=grpc")
	require.NoError(t, err)

	options := outbound.Options.(*option.VMessOutboundOptions)
	require.NotNil(t, options.Transport)
	require.Equal(t, C.V2RayTransportTypeGRPC, options.Transport.Type)
}

func TestParseVMessLinkHostServerNameFallback(t *testing.T) {
	testCases := []struct {
		name       string
		link       string
		serverName string
	}{
		{
			"websocket host",
			`{"add":"192.0.2.1","port":"443","id":"11111111-1111-1111-1111-111111111111","tls":"tls","net":"ws","host":"example.com"}`,
			"example.com",
		},
		{
			"http2 host",
			`{"add":"192.0.2.1","port":"443","id":"11111111-1111-1111-1111-111111111111","tls":"tls","net":"h2","host":"example.com"}`,
			"example.com",
		},
		{
			"explicit sni",
			`{"add":"192.0.2.1","port":"443","id":"11111111-1111-1111-1111-111111111111","tls":"tls","net":"ws","host":"host.example","sni":"sni.example"}`,
			"sni.example",
		},
		{
			"domain server",
			`{"add":"server.example","port":"443","id":"11111111-1111-1111-1111-111111111111","tls":"tls","net":"ws","host":"host.example"}`,
			"server.example",
		},
		{
			"grpc host",
			`{"add":"192.0.2.1","port":"443","id":"11111111-1111-1111-1111-111111111111","tls":"tls","net":"grpc","host":"example.com"}`,
			"192.0.2.1",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			link := "vmess://" + base64.RawURLEncoding.EncodeToString([]byte(testCase.link))
			outbound, err := ParseSubscriptionLink(link)
			require.NoError(t, err)

			options := outbound.Options.(*option.VMessOutboundOptions)
			require.Equal(t, testCase.serverName, options.TLS.ServerName)
		})
	}
}

func TestParseVLESSLinkHostServerNameFallback(t *testing.T) {
	const linkPrefix = "vless://11111111-1111-1111-1111-111111111111@"
	testCases := []struct {
		name       string
		link       string
		serverName string
	}{
		{
			"websocket host",
			"192.0.2.1:443?security=tls&type=ws&host=example.com",
			"example.com",
		},
		{
			"http host",
			"192.0.2.1:443?security=tls&type=http&host=example.com",
			"example.com",
		},
		{
			"explicit sni",
			"192.0.2.1:443?security=tls&type=ws&host=host.example&sni=sni.example",
			"sni.example",
		},
		{
			"domain server",
			"server.example:443?security=tls&type=ws&host=host.example",
			"server.example",
		},
		{
			"reality",
			"192.0.2.1:443?security=reality&type=ws&host=example.com",
			"192.0.2.1",
		},
		{
			"grpc host",
			"192.0.2.1:443?security=tls&type=grpc&host=example.com",
			"192.0.2.1",
		},
		{
			"host with port",
			"192.0.2.1:443?security=tls&type=ws&host=example.com%3A443",
			"192.0.2.1",
		},
		{
			"multiple http hosts",
			"192.0.2.1:443?security=tls&type=http&host=one.example%2Ctwo.example",
			"192.0.2.1",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			outbound, err := ParseSubscriptionLink(linkPrefix + testCase.link)
			require.NoError(t, err)

			options := outbound.Options.(*option.VLESSOutboundOptions)
			require.Equal(t, testCase.serverName, options.TLS.ServerName)
		})
	}
}

func TestParseV2RayLinkHostServerNameFallbackRequiresTLS(t *testing.T) {
	vmessLink := "vmess://" + base64.RawURLEncoding.EncodeToString([]byte(`{"add":"192.0.2.1","port":"443","id":"11111111-1111-1111-1111-111111111111","net":"ws","host":"example.com"}`))
	vmessOutbound, err := ParseSubscriptionLink(vmessLink)
	require.NoError(t, err)
	require.Nil(t, vmessOutbound.Options.(*option.VMessOutboundOptions).TLS)

	vlessOutbound, err := ParseSubscriptionLink("vless://11111111-1111-1111-1111-111111111111@192.0.2.1:443?type=ws&host=example.com")
	require.NoError(t, err)
	require.Nil(t, vlessOutbound.Options.(*option.VLESSOutboundOptions).TLS)
}

func TestParseHysteria2LinkOptions(t *testing.T) {
	outbound, err := ParseSubscriptionLink("hysteria2://password@192.0.2.1:443?sni=example.com&mport=40000-50000")
	require.NoError(t, err)

	options := outbound.Options.(*option.Hysteria2OutboundOptions)
	require.Equal(t, []string{"40000:50000"}, []string(options.ServerPorts))
	require.Equal(t, "example.com", options.TLS.ServerName)
}

func TestParseHysteria2LinkALPN(t *testing.T) {
	outbound, err := ParseSubscriptionLink("hysteria2://password@192.0.2.1:443?alpn=h3,h2")
	require.NoError(t, err)

	options := outbound.Options.(*option.Hysteria2OutboundOptions)
	require.Equal(t, []string{"h3", "h2"}, []string(options.TLS.ALPN))
}

func TestParseVLESSLinkWebsocketEarlyDataHeaderName(t *testing.T) {
	outbound, err := ParseSubscriptionLink("vless://11111111-1111-1111-1111-111111111111@192.0.2.1:443?type=ws&path=/?ed=2560&eh=X-Custom-Header")
	require.NoError(t, err)

	options := outbound.Options.(*option.VLESSOutboundOptions)
	require.Equal(t, "X-Custom-Header", options.Transport.WebsocketOptions.EarlyDataHeaderName)
}

func TestParseShadowsocksLinkUDPOverTCP(t *testing.T) {
	outbound, err := ParseSubscriptionLink("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@192.0.2.1:8388?uot=1")
	require.NoError(t, err)

	options := outbound.Options.(*option.ShadowsocksOutboundOptions)
	require.NotNil(t, options.UDPOverTCP)
	require.True(t, options.UDPOverTCP.Enabled)
}

func TestParseHysteriaLinkMbpsAlias(t *testing.T) {
	outbound, err := ParseSubscriptionLink("hysteria://192.0.2.1:443?auth=password&upmbps=100&downmbps=200")
	require.NoError(t, err)

	options := outbound.Options.(*option.HysteriaOutboundOptions)
	require.Equal(t, 100, options.UpMbps)
	require.Equal(t, 200, options.DownMbps)
}

func TestParseShadowsocksLinkLegacyFullBase64(t *testing.T) {
	link := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:oZIoA69Q8yhcQV8ka3Pa3A@192.0.2.1:8080")) + "#TEST"
	outbound, err := ParseSubscriptionLink(link)
	require.NoError(t, err)

	require.Equal(t, "TEST", outbound.Tag)
	options := outbound.Options.(*option.ShadowsocksOutboundOptions)
	require.Equal(t, "chacha20-ietf-poly1305", options.Method)
	require.Equal(t, "oZIoA69Q8yhcQV8ka3Pa3A", options.Password)
	require.Equal(t, "192.0.2.1", options.Server)
	require.Equal(t, uint16(8080), options.ServerPort)
}

func TestParseAnyTLSLinkPasswordOnly(t *testing.T) {
	// Standard format: password in userinfo (username position)
	outbound, err := ParseSubscriptionLink("anytls://mypassword@192.0.2.1:8443?sni=example.com#test")
	require.NoError(t, err)

	require.Equal(t, "test", outbound.Tag)
	options := outbound.Options.(*option.AnyTLSOutboundOptions)
	require.Equal(t, "mypassword", options.Password)
	require.Equal(t, "192.0.2.1", options.Server)
	require.Equal(t, uint16(8443), options.ServerPort)
	require.Equal(t, "example.com", options.TLS.ServerName)
}

func TestParseAnyTLSLinkWithUsernamePassword(t *testing.T) {
	// Compatibility format: username:password
	outbound, err := ParseSubscriptionLink("anytls://user:pass@192.0.2.1:8443")
	require.NoError(t, err)

	options := outbound.Options.(*option.AnyTLSOutboundOptions)
	require.Equal(t, "pass", options.Password)
	require.Equal(t, "192.0.2.1", options.Server)
	require.Equal(t, uint16(8443), options.ServerPort)
}

func TestParseAnyTLSLinkInsecure(t *testing.T) {
	outbound, err := ParseSubscriptionLink("anytls://password@192.0.2.1:8443?insecure=1")
	require.NoError(t, err)

	options := outbound.Options.(*option.AnyTLSOutboundOptions)
	require.True(t, options.TLS.Insecure)
}

func TestParseTrojanLinkGRPCServiceName(t *testing.T) {
	// Test grpc-service-name parameter (Clash style)
	outbound, err := ParseSubscriptionLink("trojan://password@192.0.2.1:443?type=grpc&grpc-service-name=my-service&sni=example.com")
	require.NoError(t, err)

	options := outbound.Options.(*option.TrojanOutboundOptions)
	require.NotNil(t, options.Transport)
	require.Equal(t, C.V2RayTransportTypeGRPC, options.Transport.Type)
	require.Equal(t, "my-service", options.Transport.GRPCOptions.ServiceName)
	require.Equal(t, "example.com", options.TLS.ServerName)
}

func TestParseTrojanLinkGRPCServiceNameAlias(t *testing.T) {
	// Test serviceName parameter (Xray/V2Ray style)
	outbound, err := ParseSubscriptionLink("trojan://password@192.0.2.1:443?type=grpc&serviceName=my-service")
	require.NoError(t, err)

	options := outbound.Options.(*option.TrojanOutboundOptions)
	require.NotNil(t, options.Transport)
	require.Equal(t, C.V2RayTransportTypeGRPC, options.Transport.Type)
	require.Equal(t, "my-service", options.Transport.GRPCOptions.ServiceName)
}

func TestParseTrojanLinkGRPCServiceNamePriority(t *testing.T) {
	// When both parameters exist, grpc-service-name takes priority
	outbound, err := ParseSubscriptionLink("trojan://password@192.0.2.1:443?type=grpc&grpc-service-name=priority-service&serviceName=fallback-service")
	require.NoError(t, err)

	options := outbound.Options.(*option.TrojanOutboundOptions)
	require.Equal(t, "priority-service", options.Transport.GRPCOptions.ServiceName)
}

func TestParseHysteria2LinkPinSHA256(t *testing.T) {
	// Test pinSHA256 certificate public key fingerprint
	pinHash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	outbound, err := ParseSubscriptionLink("hysteria2://password@192.0.2.1:443?sni=example.com&pinSHA256=" + pinHash)
	require.NoError(t, err)

	options := outbound.Options.(*option.Hysteria2OutboundOptions)
	require.Equal(t, "example.com", options.TLS.ServerName)
	require.Len(t, options.TLS.CertificatePublicKeySHA256, 1)
	require.Len(t, options.TLS.CertificatePublicKeySHA256[0], 32)

	// Verify the decoded hash matches the hex string
	expectedHash, _ := hex.DecodeString(pinHash)
	require.Equal(t, expectedHash, []byte(options.TLS.CertificatePublicKeySHA256[0]))
}

func TestParseHysteria2LinkPinSHA256Invalid(t *testing.T) {
	// Invalid hex string should be ignored
	outbound, err := ParseSubscriptionLink("hysteria2://password@192.0.2.1:443?pinSHA256=invalid_hex")
	require.NoError(t, err)

	options := outbound.Options.(*option.Hysteria2OutboundOptions)
	require.Len(t, options.TLS.CertificatePublicKeySHA256, 0)
}

func TestParseHysteria2LinkPinSHA256WrongLength(t *testing.T) {
	// Wrong length (not 32 bytes) should be ignored
	outbound, err := ParseSubscriptionLink("hysteria2://password@192.0.2.1:443?pinSHA256=abcd")
	require.NoError(t, err)

	options := outbound.Options.(*option.Hysteria2OutboundOptions)
	require.Len(t, options.TLS.CertificatePublicKeySHA256, 0)
}

func TestParseHysteria2LinkGeckoObfs(t *testing.T) {
	// Test gecko obfs with explicit type
	outbound, err := ParseSubscriptionLink("hysteria2://password@192.0.2.1:443?obfs=gecko&obfs-password=secret")
	require.NoError(t, err)

	options := outbound.Options.(*option.Hysteria2OutboundOptions)
	require.NotNil(t, options.Obfs)
	require.Equal(t, "gecko", options.Obfs.Type)
	require.Equal(t, "secret", options.Obfs.Password)
}

func TestParseHysteria2LinkGeckoObfsWithPacketSize(t *testing.T) {
	// Test gecko obfs with min/max packet size
	outbound, err := ParseSubscriptionLink("hysteria2://password@192.0.2.1:443?obfs=gecko&obfs-password=secret&obfs-min-packet-size=100&obfs-max-packet-size=200")
	require.NoError(t, err)

	options := outbound.Options.(*option.Hysteria2OutboundOptions)
	require.NotNil(t, options.Obfs)
	require.Equal(t, "gecko", options.Obfs.Type)
	require.Equal(t, "secret", options.Obfs.Password)
	require.Equal(t, 100, options.Obfs.GeckoOptions.MinPacketSize)
	require.Equal(t, 200, options.Obfs.GeckoOptions.MaxPacketSize)
}

func TestParseHysteria2LinkSalamanderObfs(t *testing.T) {
	// Test salamander obfs
	outbound, err := ParseSubscriptionLink("hysteria2://password@192.0.2.1:443?obfs=salamander&obfs-password=secret")
	require.NoError(t, err)

	options := outbound.Options.(*option.Hysteria2OutboundOptions)
	require.NotNil(t, options.Obfs)
	require.Equal(t, "salamander", options.Obfs.Type)
	require.Equal(t, "secret", options.Obfs.Password)
}

func TestParseVMessLinkURLStyleGRPCServiceName(t *testing.T) {
	// Test gRPC with serviceName parameter (should take priority over host)
	outbound, err := ParseSubscriptionLink("vmess://11111111-1111-1111-1111-111111111111@192.0.2.1:443?type=grpc&serviceName=my-service&host=fallback-service&security=tls")
	require.NoError(t, err)

	options := outbound.Options.(*option.VMessOutboundOptions)
	require.NotNil(t, options.Transport)
	require.Equal(t, C.V2RayTransportTypeGRPC, options.Transport.Type)
	require.Equal(t, "my-service", options.Transport.GRPCOptions.ServiceName)
}

func TestParseVMessLinkURLStyleGRPCHostFallback(t *testing.T) {
	// Test gRPC with host parameter (fallback when serviceName not present)
	outbound, err := ParseSubscriptionLink("vmess://11111111-1111-1111-1111-111111111111@192.0.2.1:443?type=grpc&host=my-service&security=tls")
	require.NoError(t, err)

	options := outbound.Options.(*option.VMessOutboundOptions)
	require.NotNil(t, options.Transport)
	require.Equal(t, C.V2RayTransportTypeGRPC, options.Transport.Type)
	require.Equal(t, "my-service", options.Transport.GRPCOptions.ServiceName)
}

func TestParseVMessLinkURLStyleHTTPUpgrade(t *testing.T) {
	// Test HTTPUpgrade transport
	outbound, err := ParseSubscriptionLink("vmess://11111111-1111-1111-1111-111111111111@192.0.2.1:443?type=httpupgrade&host=example.com&path=/upgrade&security=tls")
	require.NoError(t, err)

	options := outbound.Options.(*option.VMessOutboundOptions)
	require.NotNil(t, options.Transport)
	require.Equal(t, C.V2RayTransportTypeHTTPUpgrade, options.Transport.Type)
	require.Equal(t, "example.com", options.Transport.HTTPUpgradeOptions.Host)
	require.Equal(t, "/upgrade", options.Transport.HTTPUpgradeOptions.Path)
}
