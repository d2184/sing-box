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
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/outbound"
	providerAdapter "github.com/sagernet/sing-box/adapter/provider"
	"github.com/sagernet/sing-box/common/hash"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/cachefile"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
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

func (c *subscriptionCacheStub) SaveSubscription(_ string, value *adapter.SavedBinary) error {
	cp := *value
	cp.Content = append([]byte(nil), value.Content...)
	cp.URLHash = append([]byte(nil), value.URLHash...)
	c.saved = &cp
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

func newTestRemoteProviderEnv(t *testing.T, cache adapter.CacheFile) (context.Context, *outbound.Manager, map[string]*option.TrojanOutboundOptions) {
	t.Helper()
	captured := make(map[string]*option.TrojanOutboundOptions)
	outReg := outbound.NewRegistry()
	outbound.Register[option.TrojanOutboundOptions](outReg, C.TypeTrojan, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TrojanOutboundOptions) (adapter.Outbound, error) {
		optsCopy := options
		captured[tag] = &optsCopy
		return trojan.NewOutbound(ctx, router, logger, tag, options)
	})
	epReg := endpoint.NewRegistry()
	epMgr := endpoint.NewManager(epReg)
	outMgr := outbound.NewManager(outReg, epMgr, "")
	ctx := context.Background()
	ctx = service.ContextWith[adapter.OutboundRegistry](ctx, outReg)
	ctx = service.ContextWith[option.OutboundOptionsRegistry](ctx, outReg)
	ctx = service.ContextWith[adapter.EndpointRegistry](ctx, epReg)
	ctx = service.ContextWith[option.EndpointOptionsRegistry](ctx, epReg)
	ctx = service.ContextWith[adapter.OutboundManager](ctx, outMgr)
	ctx = service.ContextWith[adapter.EndpointManager](ctx, epMgr)
	if cache != nil {
		ctx = service.ContextWith[adapter.CacheFile](ctx, cache)
	}
	return ctx, outMgr, captured
}

func TestProviderRemoteCacheReappliesOverridesAndFilters(t *testing.T) {
	t.Parallel()
	const subBody = `{"outbounds":[` +
		`{"type":"trojan","tag":"alpha","server":"127.0.0.1","server_port":443,"password":"p","tls":{"enabled":true,"server_name":"a.example.com"}},` +
		`{"type":"trojan","tag":"beta","server":"127.0.0.1","server_port":443,"password":"p","tls":{"enabled":true,"server_name":"b.example.com"}}` +
		`]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Etag", `"v1"`)
		_, _ = io.WriteString(w, subBody)
	}))
	defer server.Close()

	for _, withPath := range []bool{false, true} {
		name := "cache_file_only"
		if withPath {
			name = "path_and_cache_file"
		}
		t.Run(name, func(t *testing.T) {
			cache := &subscriptionCacheStub{}
			var cachePath string
			if withPath {
				cachePath = filepath.Join(t.TempDir(), "sub.json")
			}

			// First run: connect_timeout=1s, include=alpha.
			ctx1, _, captured1 := newTestRemoteProviderEnv(t, cache)
			p1Iface, err := NewProviderRemote(ctx1, nil, log.NewNOPFactory(), "sub", option.ProviderRemoteOptions{
				URL:            server.URL,
				Path:           cachePath,
				Include:        (*badoption.Regexp)(regexp.MustCompile("^alpha$")),
				OverrideDialer: &option.OverrideDialerOptions{ConnectTimeout: common.Ptr(badoption.Duration(time.Second))},
			})
			require.NoError(t, err)
			p1 := p1Iface.(*ProviderRemote)
			p1.cacheFile = cache
			p1.httpClient = server.Client()
			require.NoError(t, p1.fetch(ctx1, true))
			require.Contains(t, captured1, "sub/alpha")
			require.NotContains(t, captured1, "sub/beta")
			require.Equal(t, badoption.Duration(time.Second), captured1["sub/alpha"].ConnectTimeout)

			// Second run (offline cache restore): connect_timeout=2s, include=beta.
			ctx2, _, captured2 := newTestRemoteProviderEnv(t, cache)
			p2Iface, err := NewProviderRemote(ctx2, nil, log.NewNOPFactory(), "sub", option.ProviderRemoteOptions{
				URL:            server.URL,
				Path:           cachePath,
				Include:        (*badoption.Regexp)(regexp.MustCompile("^beta$")),
				OverrideDialer: &option.OverrideDialerOptions{ConnectTimeout: common.Ptr(badoption.Duration(2 * time.Second))},
			})
			require.NoError(t, err)
			p2 := p2Iface.(*ProviderRemote)
			p2.cacheFile = cache
			loaded, err := p2.loadCacheFile()
			require.NoError(t, err)
			require.True(t, loaded)
			require.NotContains(t, captured2, "sub/alpha")
			require.Contains(t, captured2, "sub/beta")
			require.Equal(t, badoption.Duration(2*time.Second), captured2["sub/beta"].ConnectTimeout)
		})
	}
}

func TestProviderRemoteNotModifiedUpdatesPathAndHashTogether(t *testing.T) {
	t.Parallel()
	const subBody = `{"outbounds":[{"type":"trojan","tag":"alpha","server":"127.0.0.1","server_port":443,"password":"p","tls":{"enabled":true,"server_name":"a.example.com"}}]}`
	var step atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch step.Add(1) {
		case 1:
			w.Header().Set("Etag", `"v1"`)
			w.Header().Set("subscription-userinfo", "upload=1; download=2; total=100; expire=999")
			_, _ = io.WriteString(w, subBody)
		case 2:
			require.Equal(t, `"v1"`, r.Header.Get("If-None-Match"))
			w.Header().Set("subscription-userinfo", "upload=50; download=60; total=100; expire=999")
			w.WriteHeader(http.StatusNotModified)
		default:
			require.Equal(t, `"v1"`, r.Header.Get("If-None-Match"))
			// Intentionally omit subscription-userinfo header on 304.
			w.WriteHeader(http.StatusNotModified)
		}
	}))
	defer server.Close()

	cache := &subscriptionCacheStub{}
	cachePath := filepath.Join(t.TempDir(), "sub.json")
	ctx, _, _ := newTestRemoteProviderEnv(t, cache)
	pIface, err := NewProviderRemote(ctx, nil, log.NewNOPFactory(), "sub", option.ProviderRemoteOptions{
		URL:  server.URL,
		Path: cachePath,
	})
	require.NoError(t, err)
	p := pIface.(*ProviderRemote)
	p.cacheFile = cache
	p.httpClient = server.Client()

	// 1. Initial 200 OK.
	require.NoError(t, p.fetch(ctx, true))
	// 2. 304 with updated subscription-userinfo.
	require.NoError(t, p.fetch(ctx, false))
	require.Equal(t, int64(50), p.SubscriptionInfo().Upload)

	// Restart & reload from disk + cache must validate hash cleanly.
	ctxReload1, _, _ := newTestRemoteProviderEnv(t, cache)
	pReload1Iface, err := NewProviderRemote(ctxReload1, nil, log.NewNOPFactory(), "sub", option.ProviderRemoteOptions{
		URL:  server.URL,
		Path: cachePath,
	})
	require.NoError(t, err)
	pReload1 := pReload1Iface.(*ProviderRemote)
	pReload1.cacheFile = cache
	loaded, err := pReload1.loadCacheFile()
	require.NoError(t, err)
	require.True(t, loaded)
	require.Equal(t, int64(50), pReload1.SubscriptionInfo().Upload)

	// 3. 304 with omitted subscription-userinfo preserves prior subscription info.
	pReload1.httpClient = server.Client()
	require.NoError(t, pReload1.fetch(ctxReload1, false))
	require.Equal(t, int64(50), pReload1.SubscriptionInfo().Upload)

	// Restart & reload again must still validate hash cleanly and preserve subscription info.
	ctxReload2, _, _ := newTestRemoteProviderEnv(t, cache)
	pReload2Iface, err := NewProviderRemote(ctxReload2, nil, log.NewNOPFactory(), "sub", option.ProviderRemoteOptions{
		URL:  server.URL,
		Path: cachePath,
	})
	require.NoError(t, err)
	pReload2 := pReload2Iface.(*ProviderRemote)
	pReload2.cacheFile = cache
	loaded, err = pReload2.loadCacheFile()
	require.NoError(t, err)
	require.True(t, loaded)
	require.Equal(t, int64(50), pReload2.SubscriptionInfo().Upload)
}

func TestProviderRemoteNotModifiedWithoutPathPreservesSubscriptionInfo(t *testing.T) {
	t.Parallel()
	const subBody = `{"outbounds":[{"type":"trojan","tag":"alpha","server":"127.0.0.1","server_port":443,"password":"p","tls":{"enabled":true,"server_name":"a.example.com"}}]}`
	var step atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if step.Add(1) == 1 {
			w.Header().Set("Etag", `"v1"`)
			w.Header().Set("subscription-userinfo", "upload=7; download=8; total=100; expire=999")
			_, _ = io.WriteString(w, subBody)
			return
		}
		require.Equal(t, `"v1"`, r.Header.Get("If-None-Match"))
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	cache := &subscriptionCacheStub{}
	ctx1, _, _ := newTestRemoteProviderEnv(t, cache)
	p1Iface, err := NewProviderRemote(ctx1, nil, log.NewNOPFactory(), "sub", option.ProviderRemoteOptions{URL: server.URL})
	require.NoError(t, err)
	p1 := p1Iface.(*ProviderRemote)
	p1.cacheFile = cache
	p1.httpClient = server.Client()
	require.NoError(t, p1.fetch(ctx1, true))
	require.NoError(t, p1.fetch(ctx1, false))
	require.Equal(t, int64(7), p1.SubscriptionInfo().Upload)

	ctx2, _, _ := newTestRemoteProviderEnv(t, cache)
	p2Iface, err := NewProviderRemote(ctx2, nil, log.NewNOPFactory(), "sub", option.ProviderRemoteOptions{URL: server.URL})
	require.NoError(t, err)
	p2 := p2Iface.(*ProviderRemote)
	p2.cacheFile = cache
	loaded, err := p2.loadCacheFile()
	require.NoError(t, err)
	require.True(t, loaded)
	require.Equal(t, int64(7), p2.SubscriptionInfo().Upload)
}

func TestProviderRemoteLegacyProcessedCacheForcesUnconditionalRefresh(t *testing.T) {
	t.Parallel()
	const rawBody = `{"outbounds":[{"type":"trojan","tag":"alpha","server":"127.0.0.1","server_port":443,"password":"p","tls":{"enabled":true,"server_name":"a.example.com"}}]}`
	const legacyProcessed = `{"outbounds":[{"type":"trojan","tag":"alpha","server":"127.0.0.1","server_port":443,"password":"p","tls":{"enabled":true,"insecure":true,"server_name":"a.example.com"}}]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"old-etag"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Etag", `"old-etag"`)
		_, _ = io.WriteString(w, rawBody)
	}))
	defer server.Close()

	cache := &subscriptionCacheStub{
		saved: &adapter.SavedBinary{
			Content:     []byte(legacyProcessed),
			LastEtag:    `"old-etag"`,
			LastUpdated: time.Now(),
		},
	}
	ctx, _, captured := newTestRemoteProviderEnv(t, cache)
	pIface, err := NewProviderRemote(ctx, nil, log.NewNOPFactory(), "sub", option.ProviderRemoteOptions{
		URL: server.URL,
	})
	require.NoError(t, err)
	p := pIface.(*ProviderRemote)
	p.cacheFile = cache
	p.httpClient = server.Client()

	loaded, err := p.loadCacheFile()
	require.NoError(t, err)
	require.True(t, loaded)
	// Legacy processed cache must drop ETag and lastUpdated so next fetch is unconditional.
	require.Empty(t, p.lastEtag)
	require.True(t, p.lastUpdated.IsZero())

	require.NoError(t, p.fetch(ctx, false))
	require.False(t, captured["sub/alpha"].TLS.Insecure)
	require.Equal(t, `"old-etag"`, p.lastEtag)
}

func TestProviderRemotePathCacheHash(t *testing.T) {
	t.Parallel()

	const etag = `"test"`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("subscription-userinfo", "upload=123")
		w.Header().Set("ETag", etag)
		_, _ = io.WriteString(w, `{"outbounds":[{"type":"socks","tag":"node","server":"127.0.0.1","server_port":1080}]}`)
	}))
	t.Cleanup(server.Close)

	registry := outbound.NewRegistry()
	socks.RegisterOutbound(registry)
	ctx := service.ContextWith[option.OutboundOptionsRegistry](t.Context(), registry)
	logFactory := log.NewNOPFactory()
	dir := t.TempDir()
	path := filepath.Join(dir, "subscription.json")
	cacheOptions := option.CacheFileOptions{Path: filepath.Join(dir, "cache.db")}
	openCache := func() (*cachefile.CacheFile, *adapter.Scope) {
		t.Helper()
		cache := cachefile.New(ctx, logFactory.Logger(), cacheOptions)
		scope := adapter.NewScope(ctx, logFactory.Logger())
		t.Cleanup(func() { require.NoError(t, scope.Close()) })
		require.NoError(t, cache.Start(adapter.StartStateInitialize, scope))
		return cache, scope
	}
	newProvider := func(cache *cachefile.CacheFile) *ProviderRemote {
		t.Helper()
		endpointManager := endpoint.NewManager(endpoint.NewRegistry())
		providerCtx := service.ContextWith[adapter.EndpointManager](ctx, endpointManager)
		providerCtx = service.ContextWith[adapter.OutboundManager](providerCtx, outbound.NewManager(registry, endpointManager, ""))
		provider, err := NewProviderRemote(providerCtx, nil, logFactory, "test", option.ProviderRemoteOptions{URL: server.URL, Path: path})
		require.NoError(t, err)
		remote := provider.(*ProviderRemote)
		t.Cleanup(func() { require.NoError(t, remote.Close()) })
		remote.cacheFile = cache
		remote.httpClient = server.Client()
		return remote
	}

	cache, scope := openCache()
	require.NoError(t, newProvider(cache).fetch(ctx, true))
	require.NoError(t, scope.Close())
	cache, _ = openCache()

	provider := newProvider(cache)
	loaded, err := provider.loadCacheFile()
	require.NoError(t, err)
	require.True(t, loaded)
	require.Equal(t, etag, provider.lastEtag)
	require.EqualValues(t, 123, provider.SubscriptionInfo().Upload)

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, append(content, '\n'), 0o600))
	loaded, err = newProvider(cache).loadCacheFile()
	require.ErrorContains(t, err, "validation failed")
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
		`{"type":"socks","tag":"A","server":"127.0.0.1","server_port":1080,"detour":"prov/B"},` +
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

func TestProviderRemoteRejectsRemovedDetour(test *testing.T) {
	const client = `{"type":"socks","tag":"A","server":"127.0.0.1","server_port":1080,"detour":"B"}`
	const upstream = `{"type":"socks","tag":"B","server":"127.0.0.1","server_port":1081}`
	var subscription atomic.Value
	subscription.Store(`{"outbounds":[` + client + `,` + upstream + `]}`)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(response, subscription.Load().(string))
	}))
	test.Cleanup(server.Close)
	cache := &subscriptionCacheStub{}
	provider, detours := newCacheTestProvider(cache, server.URL)
	provider.httpClient = server.Client()
	fallback := "new-detour"
	provider.overrideDialer = &option.OverrideDialerOptions{Detour: &fallback}
	ctx := context.Background()
	require.NoError(test, provider.fetch(ctx, true))
	oldNodes, oldCache := provider.Outbounds(), cache.saved
	require.Equal(test, "prov/B", detours["prov/A"])

	subscription.Store(`{"outbounds":[` + client + `]}`)
	require.EqualError(test, provider.fetch(ctx, false), "cannot remove provider node [prov/B]: still referenced by [prov/A]")
	require.Equal(test, oldNodes, provider.Outbounds())
	require.Same(test, oldCache, cache.saved)

	subscription.Store(`{"outbounds":[` + strings.Replace(client, `"detour":"B"`, `"detour":"external"`, 1) + `]}`)
	require.NoError(test, provider.fetch(ctx, false))
	require.Equal(test, fallback, detours["prov/A"])
	_, found := provider.Outbound("prov/B")
	require.False(test, found)
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
				require.True(t, strings.HasPrefix(string(content), rawCacheHeader+"\n"))
				require.Equal(t, test.initial != "" || test.update != "", strings.HasPrefix(string(content), rawCacheHeader+"\n# "))
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
				require.True(t, strings.HasPrefix(string(content), rawCacheHeader+"\n"))
				require.Equal(t, test.initial != "" || test.update != "", strings.HasPrefix(string(content), rawCacheHeader+"\n# "))
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
	require.True(t, strings.HasPrefix(string(cache.saved.Content), rawCacheHeader+"\n# "+info+";\n"))
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
