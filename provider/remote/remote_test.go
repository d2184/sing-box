package remote

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/outbound"
	providerAdapter "github.com/sagernet/sing-box/adapter/provider"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type subscriptionCacheStub struct {
	adapter.CacheFile
	saved *adapter.SavedBinary
}

func (c *subscriptionCacheStub) LoadSubscription(string) *adapter.SavedBinary {
	return c.saved
}

func (c *subscriptionCacheStub) SaveSubscription(_ string, saved *adapter.SavedBinary) error {
	c.saved = saved
	return nil
}

type stubNode struct {
	outbound.Adapter
}

func (*stubNode) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("unsupported")
}

func (*stubNode) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unsupported")
}

// newCacheTestProvider returns a provider backed by stub outbounds and a map
// recording the detour each vmess node was created with, keyed by node tag.
func newCacheTestProvider(cache adapter.CacheFile, url string) (*ProviderRemote, map[string]string) {
	detours := make(map[string]string)
	registry := outbound.NewRegistry()
	outbound.Register[option.SOCKSOutboundOptions](registry, C.TypeSOCKS, func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ option.SOCKSOutboundOptions) (adapter.Outbound, error) {
		return &stubNode{Adapter: outbound.NewAdapter(C.TypeSOCKS, tag, []string{"tcp"}, nil)}, nil
	})
	outbound.Register[option.VMessOutboundOptions](registry, C.TypeVMess, func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options option.VMessOutboundOptions) (adapter.Outbound, error) {
		if tag == "prov/bad" {
			return nil, errors.New("stub vmess construction failure")
		}
		detours[tag] = options.DialerOptions.Detour
		return &stubNode{Adapter: outbound.NewAdapter(C.TypeVMess, tag, []string{"tcp"}, nil)}, nil
	})
	ctx := service.ContextWith[option.OutboundOptionsRegistry](context.Background(), registry)
	logFactory := log.NewNOPFactory()
	logger := logFactory.NewLogger("test")
	endpoints := endpoint.NewManager(endpoint.NewRegistry())
	outbounds := outbound.NewManager(registry, endpoints, "")
	return &ProviderRemote{
		Adapter: providerAdapter.NewAdapter(
			ctx,
			nil,
			outbounds,
			endpoints,
			logFactory,
			logger,
			"prov",
			C.ProviderTypeRemote,
			option.ProviderHealthCheckOptions{},
		),
		ctx:       ctx,
		logger:    logger,
		url:       url,
		urlHash:   sha256.Sum256([]byte(url)),
		cacheFile: cache,
	}, detours
}

func TestProviderRemoteURLHash(t *testing.T) {
	t.Parallel()

	const providerURL = "https://example.com/provider"
	provider, err := NewProviderRemote(
		context.Background(),
		nil,
		log.NewNOPFactory(),
		"test",
		option.ProviderRemoteOptions{URL: providerURL},
	)
	require.NoError(t, err)
	require.Equal(t, sha256.Sum256([]byte(providerURL)), provider.(*ProviderRemote).urlHash)
}

func TestProviderRemoteRejectsCacheFromDifferentURL(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logFactory := log.NewNOPFactory()
	logger := logFactory.NewLogger("test")
	providerURLHash := sha256.Sum256([]byte("https://example.com/new-provider"))
	provider := &ProviderRemote{
		Adapter: providerAdapter.NewAdapter(
			ctx,
			nil,
			nil,
			nil,
			logFactory,
			logger,
			"test",
			C.ProviderTypeRemote,
			option.ProviderHealthCheckOptions{},
		),
		ctx:     ctx,
		logger:  logger,
		urlHash: providerURLHash,
		cacheFile: &subscriptionCacheStub{saved: &adapter.SavedBinary{
			Content: []byte("invalid provider content must not be parsed"),
			URLHash: []byte("different URL hash"),
		}},
	}

	loaded, err := provider.loadCacheFile()
	require.NoError(t, err)
	require.False(t, loaded)
}

func TestProviderRemoteCacheLoadsWhenSomeNodesFail(t *testing.T) {
	t.Parallel()

	const nodes = `{"outbounds":[` +
		`{"type":"socks","tag":"good","server":"127.0.0.1","server_port":1080},` +
		`{"type":"vmess","tag":"bad","server":"127.0.0.1","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}`
	cache := &subscriptionCacheStub{saved: &adapter.SavedBinary{Content: []byte(nodes)}}
	provider, _ := newCacheTestProvider(cache, "https://example.com")

	loaded, err := provider.loadCacheFile()
	require.NoError(t, err)
	require.True(t, loaded)
	_, found := provider.Outbound("prov/good")
	require.True(t, found)
	_, found = provider.Outbound("prov/bad")
	require.False(t, found)
}

func TestProviderRemoteCacheReloadKeepsDetour(t *testing.T) {
	t.Parallel()

	const subscription = `{"outbounds":[` +
		`{"type":"socks","tag":"A","server":"127.0.0.1","server_port":1080},` +
		`{"type":"vmess","tag":"B","server":"127.0.0.1","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","detour":"A"}]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, subscription)
	}))
	defer server.Close()

	cache := &subscriptionCacheStub{}
	first, firstDetours := newCacheTestProvider(cache, server.URL)
	first.httpClient = server.Client()
	require.NoError(t, first.fetch(context.Background(), true))
	require.Equal(t, "prov/A", firstDetours["prov/B"])

	second, secondDetours := newCacheTestProvider(cache, server.URL)
	loaded, err := second.loadCacheFile()
	require.NoError(t, err)
	require.True(t, loaded)
	require.Equal(t, "prov/A", secondDetours["prov/B"])
}

// TestProviderRemoteCacheSubscriptionInfo fetches once (200), optionally fetches again
// (304), then loads the cache with a fresh provider and checks the restored info.
func TestProviderRemoteCacheSubscriptionInfo(t *testing.T) {
	t.Parallel()

	const (
		subscription = `{"outbounds":[{"type":"socks","tag":"A","server":"127.0.0.1","server_port":1080}]}`
		infoFirst    = "upload=1; download=2; total=30; expire=40"
		infoSecond   = "upload=10; download=20; total=30; expire=40"
	)
	first := adapter.SubscriptionInfo{Upload: 1, Download: 2, Total: 30, Expire: 40}
	second := adapter.SubscriptionInfo{Upload: 10, Download: 20, Total: 30, Expire: 40}
	for _, testCase := range []struct {
		name       string
		usePath    bool
		infoOn200  string
		infoOn304  string
		notModifed bool
		expected   adapter.SubscriptionInfo
	}{
		{name: "no path, info on 200", infoOn200: infoFirst, expected: first},
		{name: "no path, info changes on 304", infoOn200: infoFirst, infoOn304: infoSecond, notModifed: true, expected: second},
		{name: "no path, info only on 304", infoOn304: infoSecond, notModifed: true, expected: second},
		{name: "no path, 304 without info keeps info", infoOn200: infoFirst, notModifed: true, expected: first},
		{name: "path, info on 200", usePath: true, infoOn200: infoFirst, expected: first},
		{name: "path, info changes on 304", usePath: true, infoOn200: infoFirst, infoOn304: infoSecond, notModifed: true, expected: second},
		{name: "path, info only on 304", usePath: true, infoOn304: infoSecond, notModifed: true, expected: second},
		{name: "path, 304 without info keeps info", usePath: true, infoOn200: infoFirst, notModifed: true, expected: first},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("If-None-Match") != "" {
					if testCase.infoOn304 != "" {
						w.Header().Set("subscription-userinfo", testCase.infoOn304)
					}
					w.WriteHeader(http.StatusNotModified)
					return
				}
				w.Header().Set("Etag", "e1")
				if testCase.infoOn200 != "" {
					w.Header().Set("subscription-userinfo", testCase.infoOn200)
				}
				io.WriteString(w, subscription)
			}))
			defer server.Close()

			var path string
			if testCase.usePath {
				path = filepath.Join(t.TempDir(), "cache.json")
			}
			cache := &subscriptionCacheStub{}
			before, _ := newCacheTestProvider(cache, server.URL)
			before.path = path
			before.httpClient = server.Client()
			require.NoError(t, before.fetch(context.Background(), true))
			if testCase.notModifed {
				require.NoError(t, before.fetch(context.Background(), false))
			}
			require.Equal(t, testCase.expected, before.SubscriptionInfo())

			after, _ := newCacheTestProvider(cache, server.URL)
			after.path = path
			loaded, err := after.loadCacheFile()
			require.NoError(t, err)
			require.True(t, loaded)
			require.Equal(t, testCase.expected, after.SubscriptionInfo())
		})
	}
}

func TestProviderRemoteCacheInfoLine(t *testing.T) {
	t.Parallel()

	const compact = `{"outbounds":[{"type":"socks","tag":"n total=1","server":"127.0.0.1","server_port":1080}]}`
	t.Run("document text is not an info line", func(t *testing.T) {
		t.Parallel()
		cache := &subscriptionCacheStub{saved: &adapter.SavedBinary{Content: []byte(compact)}}
		provider, _ := newCacheTestProvider(cache, "https://example.com")
		loaded, err := provider.loadCacheFile()
		require.NoError(t, err)
		require.True(t, loaded)
		require.Equal(t, adapter.SubscriptionInfo{}, provider.SubscriptionInfo())
	})
	for name, firstLine := range map[string]string{
		"hash-prefixed info line is stripped": "# upload=1; download=2; total=3; expire=4;",
		"raw header info line is stripped":    "upload=1; download=2; total=3; expire=4",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cache := &subscriptionCacheStub{saved: &adapter.SavedBinary{Content: []byte(firstLine + "\n" + compact)}}
			provider, _ := newCacheTestProvider(cache, "https://example.com")
			loaded, err := provider.loadCacheFile()
			require.NoError(t, err)
			require.True(t, loaded)
			require.Equal(t, adapter.SubscriptionInfo{Upload: 1, Download: 2, Total: 3, Expire: 4}, provider.SubscriptionInfo())
		})
	}
}
