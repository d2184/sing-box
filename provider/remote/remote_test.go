package remote

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/outbound"
	providerAdapter "github.com/sagernet/sing-box/adapter/provider"
	"github.com/sagernet/sing-box/common/hash"
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
	copy := *saved
	copy.Content = append([]byte(nil), saved.Content...)
	copy.URLHash = append([]byte(nil), saved.URLHash...)
	c.saved = &copy
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

func newCacheTestProvider(cache adapter.CacheFile, url string) (*ProviderRemote, map[string]string) {
	detours := make(map[string]string)
	registry := outbound.NewRegistry()
	outbound.Register[option.SOCKSOutboundOptions](registry, C.TypeSOCKS, func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options option.SOCKSOutboundOptions) (adapter.Outbound, error) {
		detours[tag] = options.DialerOptions.Detour
		return &stubNode{Adapter: outbound.NewAdapter(C.TypeSOCKS, tag, []string{"tcp"}, nil)}, nil
	})
	ctx := service.ContextWith[option.OutboundOptionsRegistry](context.Background(), registry)
	logFactory := log.NewNOPFactory()
	logger := logFactory.NewLogger("test")
	endpoints := endpoint.NewManager(endpoint.NewRegistry())
	outbounds := outbound.NewManager(registry, endpoints, "")
	if err := outbounds.Replace(ctx, nil, logger, "new-detour", C.TypeSOCKS, &option.SOCKSOutboundOptions{}); err != nil {
		panic(err)
	}
	return &ProviderRemote{
		Adapter: providerAdapter.NewAdapter(ctx, nil, outbounds, endpoints, logFactory, logger, "prov", C.ProviderTypeRemote, option.ProviderHealthCheckOptions{}),
		ctx:     ctx, logger: logger, url: url, urlHash: sha256.Sum256([]byte(url)), cacheFile: cache,
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

func TestProviderRemoteCacheRawNodesAndReloadOptions(t *testing.T) {
	t.Parallel()
	const subscription = `{"outbounds":[` +
		`{"type":"socks","tag":"A","server":"127.0.0.1","server_port":1080},` +
		`{"type":"socks","tag":"B","server":"127.0.0.1","server_port":1081,"detour":"original"}]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, subscription)
	}))
	defer server.Close()

	for _, usePath := range []bool{false, true} {
		t.Run(map[bool]string{false: "database", true: "file"}[usePath], func(t *testing.T) {
			cache := &subscriptionCacheStub{}
			first, _ := newCacheTestProvider(cache, server.URL)
			notifications := 0
			first.RegisterCallback(func(string) error {
				notifications++
				return nil
			})
			if usePath {
				first.path = filepath.Join(t.TempDir(), "cache.json")
			}
			first.httpClient = server.Client()
			first.include = regexp.MustCompile(`^A$`)
			require.NoError(t, first.fetch(context.Background(), true))
			require.Equal(t, 1, notifications)
			require.NotNil(t, cache.saved)
			content := cache.saved.Content
			if usePath {
				var err error
				content, err = os.ReadFile(first.path)
				require.NoError(t, err)
			}
			require.Contains(t, string(content), `"tag":"B"`)
			require.Contains(t, string(content), `"detour":"original"`)

			second, detours := newCacheTestProvider(cache, server.URL)
			second.path = first.path
			second.include = regexp.MustCompile(`^B$`)
			detour := "new-detour"
			second.overrideDialer = &option.OverrideDialerOptions{Detour: &detour}
			loaded, err := second.loadCacheFile()
			require.NoError(t, err)
			require.True(t, loaded)
			_, found := second.Outbound("prov/A")
			require.False(t, found)
			_, found = second.Outbound("prov/B")
			require.True(t, found)
			require.Equal(t, detour, detours["prov/B"])
		})
	}
}

func TestProviderRemoteFilteredDetour(t *testing.T) {
	const subscription = `{"outbounds":[` +
		`{"type":"socks","tag":"A","server":"127.0.0.1","server_port":1080,"detour":"B"},` +
		`{"type":"socks","tag":"B","server":"127.0.0.1","server_port":1081}]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, subscription)
	}))
	defer server.Close()
	cache := &subscriptionCacheStub{}
	provider, _ := newCacheTestProvider(cache, server.URL)
	provider.httpClient = server.Client()
	provider.include = regexp.MustCompile(`^A$`)
	detour := "new-detour"
	provider.overrideDialer = &option.OverrideDialerOptions{Detour: &detour}
	err := provider.fetch(context.Background(), true)
	require.ErrorContains(t, err, "provider dependency not found: prov/B")
	_, found := provider.Outbound("prov/A")
	require.False(t, found)

	cache.saved = &adapter.SavedBinary{Content: []byte(subscription)}
	restored, _ := newCacheTestProvider(cache, server.URL)
	restored.include = provider.include
	restored.overrideDialer = provider.overrideDialer
	loaded, err := restored.loadCacheFile()
	require.False(t, loaded)
	require.ErrorContains(t, err, "provider dependency not found: prov/B")
	_, found = restored.Outbound("prov/A")
	require.False(t, found)
}

func TestProviderRemoteCacheSubscriptionInfo304(t *testing.T) {
	t.Parallel()
	const subscription = `{"outbounds":[{"type":"socks","tag":"A","server":"127.0.0.1","server_port":1080}]}`
	const firstInfo = "upload=1; download=2; total=30; expire=40"
	const secondInfo = "upload=10; download=20; total=30; expire=40"
	tests := []struct {
		name     string
		initial  string
		update   string
		expected adapter.SubscriptionInfo
	}{
		{"initial-only", firstInfo, "", adapter.SubscriptionInfo{Upload: 1, Download: 2, Total: 30, Expire: 40}},
		{"both", firstInfo, secondInfo, adapter.SubscriptionInfo{Upload: 10, Download: 20, Total: 30, Expire: 40}},
		{"update-only", "", secondInfo, adapter.SubscriptionInfo{Upload: 10, Download: 20, Total: 30, Expire: 40}},
		{"neither", "", "", adapter.SubscriptionInfo{}},
	}
	for _, usePath := range []bool{false, true} {
		for _, test := range tests {
			name := map[bool]string{false: "database", true: "file"}[usePath] + "/" + test.name
			t.Run(name, func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("If-None-Match") == "e1" {
						if test.update != "" {
							w.Header().Set("subscription-userinfo", test.update)
						}
						w.WriteHeader(http.StatusNotModified)
						return
					}
					w.Header().Set("ETag", "e1")
					if test.initial != "" {
						w.Header().Set("subscription-userinfo", test.initial)
					}
					_, _ = io.WriteString(w, subscription)
				}))
				defer server.Close()
				cache := &subscriptionCacheStub{}
				before, _ := newCacheTestProvider(cache, server.URL)
				if usePath {
					before.path = filepath.Join(t.TempDir(), "cache.json")
				}
				before.httpClient = server.Client()
				require.NoError(t, before.fetch(context.Background(), true))
				previousContent := append([]byte(nil), cache.saved.Content...)
				if usePath {
					var err error
					previousContent, err = os.ReadFile(before.path)
					require.NoError(t, err)
				}
				require.NoError(t, before.fetch(context.Background(), false))
				require.Equal(t, test.expected, before.SubscriptionInfo())
				content := cache.saved.Content
				if usePath {
					var err error
					content, err = os.ReadFile(before.path)
					require.NoError(t, err)
					require.True(t, cache.saved.Hash.Equal(hash.MakeHash(content)), "database hash must match cache file")
				}
				require.Equal(t, test.initial != "" || test.update != "", strings.HasPrefix(string(content), "# "))
				if test.update == "" {
					require.Equal(t, previousContent, content)
				}
				after, _ := newCacheTestProvider(cache, server.URL)
				after.path = before.path
				loaded, err := after.loadCacheFile()
				require.NoError(t, err)
				require.True(t, loaded)
				require.Equal(t, test.expected, after.SubscriptionInfo())
				after.httpClient = server.Client()
				require.NoError(t, after.fetch(context.Background(), false))
				content = cache.saved.Content
				if usePath {
					content, err = os.ReadFile(after.path)
					require.NoError(t, err)
				}
				require.Equal(t, test.initial != "" || test.update != "", strings.HasPrefix(string(content), "# "))
			})
		}
	}
}

func TestProviderRemoteFetchJSONWithInfoLikeTag(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"outbounds":[{"type":"socks","tag":"n total=1","server":"127.0.0.1","server_port":1080}]}`)
	}))
	defer server.Close()
	cache := &subscriptionCacheStub{}
	provider, _ := newCacheTestProvider(cache, server.URL)
	provider.httpClient = server.Client()
	require.NoError(t, provider.fetch(context.Background(), true))
	restored, _ := newCacheTestProvider(cache, server.URL)
	loaded, err := restored.loadCacheFile()
	require.NoError(t, err)
	require.True(t, loaded)
	_, found := restored.Outbound("prov/n total=1")
	require.True(t, found)
	require.Equal(t, adapter.SubscriptionInfo{}, restored.SubscriptionInfo())
}

func TestProviderRemoteFetchBodyInfoLine(t *testing.T) {
	const info = "upload=1; download=2; total=3; expire=4"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "# "+info+"\n"+`{"outbounds":[{"type":"socks","tag":"A","server":"127.0.0.1","server_port":1080}]}`)
	}))
	defer server.Close()
	cache := &subscriptionCacheStub{}
	provider, _ := newCacheTestProvider(cache, server.URL)
	provider.httpClient = server.Client()
	require.NoError(t, provider.fetch(context.Background(), true))
	require.True(t, strings.HasPrefix(string(cache.saved.Content), "# "+info+"\n"))
	restored, _ := newCacheTestProvider(cache, server.URL)
	loaded, err := restored.loadCacheFile()
	require.NoError(t, err)
	require.True(t, loaded)
	require.Equal(t, adapter.SubscriptionInfo{Upload: 1, Download: 2, Total: 3, Expire: 4}, restored.SubscriptionInfo())
}

func TestProviderRemoteCacheInfoLine(t *testing.T) {
	t.Parallel()
	const compact = `{"outbounds":[{"type":"socks","tag":"n total=1","server":"127.0.0.1","server_port":1080}]}`
	for _, firstLine := range []string{"", "# upload=1; download=2; total=3; expire=4;", "upload=1; download=2; total=3; expire=4"} {
		name := firstLine
		if name == "" {
			name = "compact JSON"
		}
		t.Run(name, func(t *testing.T) {
			content := compact
			if firstLine != "" {
				content = firstLine + "\n" + compact
			}
			cache := &subscriptionCacheStub{saved: &adapter.SavedBinary{Content: []byte(content)}}
			provider, _ := newCacheTestProvider(cache, "https://example.com")
			loaded, err := provider.loadCacheFile()
			require.NoError(t, err)
			require.True(t, loaded)
			_, found := provider.Outbound("prov/n total=1")
			require.True(t, found)
			if strings.HasPrefix(content, "{") {
				require.Equal(t, adapter.SubscriptionInfo{}, provider.SubscriptionInfo())
			} else {
				require.Equal(t, adapter.SubscriptionInfo{Upload: 1, Download: 2, Total: 3, Expire: 4}, provider.SubscriptionInfo())
			}
		})
	}
}
