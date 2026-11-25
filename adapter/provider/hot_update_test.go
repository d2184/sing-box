package provider_test

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/provider"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/require"
)

type nodeOptions struct {
	option.DialerOptions
	Revision int
	Fail     bool
}
type testNode struct {
	outbound.Adapter
	options nodeOptions
	detour  *dialer.DetourDialer
	starts  atomic.Int32
	closes  atomic.Int32
	access  sync.Mutex
	conns   []net.Conn
}

func (n *testNode) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	n.starts.Add(1)
	if stage == adapter.StartStateInitialize {
		scope.Add(func() error {
			n.closes.Add(1)
			n.access.Lock()
			defer n.access.Unlock()
			for _, conn := range n.conns {
				conn.Close()
			}
			return nil
		})
	}
	if stage == adapter.StartStateStart && n.options.Fail {
		return errors.New("failed candidate")
	}
	return nil
}
func (n *testNode) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if n.closes.Load() != 0 {
		return nil, net.ErrClosed
	}
	if n.detour != nil {
		return n.detour.DialContext(ctx, network, destination)
	}
	client, server := net.Pipe()
	n.access.Lock()
	n.conns = append(n.conns, client, server)
	n.access.Unlock()
	go func() { defer server.Close(); io.Copy(server, server) }()
	return client, nil
}
func (*testNode) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unsupported")
}

type testEndpointNode struct {
	*testNode
}

func (*testEndpointNode) IsEndpoint() {}

func TestProviderHotUpdateKeepsUnchangedNodesAndConnections(t *testing.T) {
	ctx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
	factory := log.NewNOPFactory()
	logger := factory.Logger()
	registry := outbound.NewRegistry()
	var candidates []*testNode
	outbound.Register[nodeOptions](registry, "test", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options nodeOptions) (adapter.Outbound, error) {
		n := &testNode{Adapter: outbound.NewAdapter("test", tag, []string{"tcp"}, nil), options: options}
		candidates = append(candidates, n)
		return n, nil
	})
	ep := endpoint.NewManager(endpoint.NewRegistry())
	manager := outbound.NewManager(registry, ep, "")
	require.NoError(t, manager.Create(ctx, nil, logger, "static", "test", &nodeOptions{}))
	scope := adapter.NewScope(ctx, logger)
	t.Cleanup(func() { require.NoError(t, scope.Close()) })
	for _, stage := range adapter.ListStartStages {
		require.NoError(t, scope.Start("endpoint", ep, stage))
		require.NoError(t, scope.Start("outbound", manager, stage))
	}
	static, _ := manager.Outbound("static")
	p := provider.NewAdapter(ctx, nil, manager, ep, factory, logger, "subscription", "inline", option.ProviderHealthCheckOptions{})
	require.NoError(t, p.Start())
	t.Cleanup(func() { require.NoError(t, p.Close()) })
	opts := func(stableRev, changedRev int, fail bool) []option.Outbound {
		return []option.Outbound{
			{Type: "test", Tag: "stable", Options: &nodeOptions{Revision: stableRev}},
			{Type: "test", Tag: "changed", Options: &nodeOptions{Revision: changedRev, Fail: fail}},
		}
	}
	initial := opts(1, 1, false)
	p.UpdateNodes(initial, nil)
	stable, _ := p.Outbound("subscription/stable")
	changed, _ := p.Outbound("subscription/changed")
	conn, err := stable.DialContext(ctx, "tcp", M.Socksaddr{})
	require.NoError(t, err)
	defer conn.Close()
	detour := dialer.NewDetour(manager, "subscription/changed", true).(*dialer.DetourDialer)
	first, err := detour.Dialer()
	require.NoError(t, err)
	require.Same(t, changed, first)
	next := opts(1, 2, false)
	p.UpdateNodes(next, nil)
	stableAgain, _ := p.Outbound("subscription/stable")
	changedAgain, _ := p.Outbound("subscription/changed")
	require.Same(t, stable, stableAgain)
	require.NotSame(t, changed, changedAgain)
	require.EqualValues(t, 4, stable.(*testNode).starts.Load())
	require.Zero(t, stable.(*testNode).closes.Load())
	require.EqualValues(t, 1, changed.(*testNode).closes.Load())
	latest, err := detour.Dialer()
	require.NoError(t, err)
	require.Same(t, changedAgain, latest)
	staticAgain, _ := manager.Outbound("static")
	require.Same(t, static, staticAgain)
	require.Zero(t, static.(*testNode).closes.Load())
	require.NoError(t, conn.SetDeadline(time.Now().Add(time.Second)))
	done := make(chan error, 1)
	go func() { _, err := conn.Write([]byte("alive")); done <- err }()
	result := make([]byte, 5)
	_, err = io.ReadFull(conn, result)
	require.NoError(t, err)
	require.NoError(t, <-done)
	require.Equal(t, "alive", string(result))
	failed := opts(1, 3, true)
	p.UpdateNodes(failed, nil)
	retained, _ := p.Outbound("subscription/changed")
	require.Same(t, changedAgain, retained)
	require.EqualValues(t, 1, candidates[len(candidates)-1].closes.Load())
	count := len(candidates)
	p.UpdateNodes(failed, nil)
	require.Len(t, candidates, count+1, "failed updates must be retried")
	p.UpdateNodes(failed[:1], nil)
	_, found := manager.Outbound("subscription/changed")
	require.False(t, found)
	require.EqualValues(t, 1, changedAgain.(*testNode).closes.Load())
	require.NoError(t, p.Close())
	require.NoError(t, scope.Close())
	for _, n := range candidates {
		require.EqualValues(t, 1, n.closes.Load(), n.Tag())
	}
}

type testReferringEndpoint struct {
	testEndpointNode
}

func (*testReferringEndpoint) Dependencies() []string {
	return nil
}

func (node *testReferringEndpoint) References() ([]string, []string) {
	return []string{node.options.Detour}, nil
}

func TestProviderFailedUpdateKeepsOldDependencyChain(test *testing.T) {
	ctx := context.Background()
	factory := log.NewNOPFactory()
	logger := factory.Logger()
	outboundRegistry, endpointRegistry := outbound.NewRegistry(), endpoint.NewRegistry()
	endpointManager := endpoint.NewManager(endpointRegistry)
	outboundManager := outbound.NewManager(outboundRegistry, endpointManager, "")
	constructed := make(map[string]int)
	newNode := func(tag string, options nodeOptions) *testNode {
		constructed[tag]++
		node := &testNode{Adapter: outbound.NewAdapterWithDialerOptions("test", tag, []string{"tcp"}, options.DialerOptions), options: options}
		if options.Detour != "" {
			node.detour = dialer.NewDetour(outboundManager, options.Detour, true).(*dialer.DetourDialer)
		}
		return node
	}
	outbound.Register[nodeOptions](outboundRegistry, "test", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options nodeOptions) (adapter.Outbound, error) {
		return newNode(tag, options), nil
	})
	endpoint.Register[nodeOptions](endpointRegistry, "test", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options nodeOptions) (adapter.Endpoint, error) {
		return &testReferringEndpoint{testEndpointNode{testNode: newNode(tag, options)}}, nil
	})
	require.NoError(test, outboundManager.Create(ctx, nil, logger, "static", "test", &nodeOptions{}))
	scope := adapter.NewScope(ctx, logger)
	test.Cleanup(func() { require.NoError(test, scope.Close()) })
	for _, stage := range adapter.ListStartStages {
		require.NoError(test, scope.Start("endpoint", endpointManager, stage))
		require.NoError(test, scope.Start("outbound", outboundManager, stage))
	}
	subscription := provider.NewAdapter(ctx, nil, outboundManager, endpointManager, factory, logger, "provider", "inline", option.ProviderHealthCheckOptions{})
	test.Cleanup(func() { require.NoError(test, subscription.Close()) })
	withDetour := func(tag string) *nodeOptions {
		return &nodeOptions{DialerOptions: option.DialerOptions{Detour: "provider/" + tag}}
	}
	initialOutbounds := []option.Outbound{
		{Type: "test", Tag: "client", Options: withDetour("bridge")},
		{Type: "test", Tag: "relay", Options: &nodeOptions{}},
		{Type: "test", Tag: "obsolete", Options: &nodeOptions{}},
	}
	initialEndpoints := []option.Endpoint{{Type: "test", Tag: "bridge", Options: withDetour("relay")}}
	require.NoError(test, subscription.UpdateNodes(initialOutbounds, initialEndpoints))
	client, _ := subscription.Outbound("provider/client")
	bridge, _ := subscription.Outbound("provider/bridge")
	relay, _ := subscription.Outbound("provider/relay")
	initialNodes := subscription.Outbounds()
	require.EqualError(test, subscription.UpdateNodes(initialOutbounds[:1], nil), "cannot remove provider node [provider/bridge]: still referenced by [provider/client]")
	require.EqualError(test, subscription.UpdateNodes(initialOutbounds[:1], initialEndpoints), "cannot remove provider node [provider/relay]: still referenced by [provider/bridge]")
	require.Equal(test, initialNodes, subscription.Outbounds())

	nextOutbounds := []option.Outbound{
		{Type: "test", Tag: "client", Options: &nodeOptions{Fail: true}},
		{Type: "test", Tag: "dependent", Options: withDetour("client")},
		{Type: "test", Tag: "independent", Options: &nodeOptions{}},
	}
	updateErr := subscription.UpdateNodes(nextOutbounds, nil)
	require.ErrorContains(test, updateErr, "failed candidate")
	require.ErrorContains(test, updateErr, "cannot remove provider node [provider/bridge]: still referenced by previous instance of [provider/client]")
	require.ErrorContains(test, updateErr, "cannot remove provider node [provider/relay]: still referenced by previous instance of [provider/bridge]")
	retained, _ := subscription.Outbound("provider/client")
	require.Same(test, client, retained)
	conn, err := retained.DialContext(ctx, "tcp", M.Socksaddr{})
	require.NoError(test, err)
	require.NoError(test, conn.Close())
	retained, _ = subscription.Outbound("provider/bridge")
	require.Same(test, bridge, retained)
	retained, _ = subscription.Outbound("provider/relay")
	require.Same(test, relay, retained)
	_, found := outboundManager.Outbound("provider/obsolete")
	require.False(test, found)
	require.NotContains(test, constructed, "provider/dependent")
	independent, found := subscription.Outbound("provider/independent")
	require.True(test, found)
	require.Equal(test, []adapter.Outbound{client, independent, relay, bridge}, subscription.Outbounds())

	nextOutbounds[0].Options = &nodeOptions{}
	require.NoError(test, subscription.UpdateNodes(nextOutbounds, nil))
	require.Equal(test, 1, constructed["provider/dependent"])
	for _, tag := range []string{"provider/bridge", "provider/relay"} {
		_, found = subscription.Outbound(tag)
		require.False(test, found, tag)
		_, found = outboundManager.Outbound(tag)
		require.False(test, found, tag)
	}
	require.EqualValues(test, 1, bridge.(*testReferringEndpoint).closes.Load())
	require.EqualValues(test, 1, relay.(*testNode).closes.Load())
}

func TestProviderEndpointHotUpdate(t *testing.T) {
	ctx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
	factory := log.NewNOPFactory()
	logger := factory.Logger()
	registry := endpoint.NewRegistry()
	endpoint.Register[nodeOptions](registry, "test", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options nodeOptions) (adapter.Endpoint, error) {
		return &testEndpointNode{testNode: &testNode{Adapter: outbound.NewAdapter("test", tag, []string{"tcp"}, nil), options: options}}, nil
	})
	ep := endpoint.NewManager(registry)
	out := outbound.NewManager(outbound.NewRegistry(), ep, "")
	scope := adapter.NewScope(ctx, logger)
	t.Cleanup(func() { scope.Close() })
	for _, stage := range adapter.ListStartStages {
		require.NoError(t, scope.Start("endpoint", ep, stage))
	}
	p := provider.NewAdapter(ctx, nil, out, ep, factory, logger, "p", "inline", option.ProviderHealthCheckOptions{})
	require.NoError(t, p.Start())
	t.Cleanup(func() { p.Close() })
	initial := []option.Endpoint{{Type: "test", Tag: "a", Options: &nodeOptions{Revision: 1}}}
	p.UpdateNodes(nil, initial)
	old, found := ep.Get("p/a")
	require.True(t, found)
	require.EqualValues(t, 4, old.(*testEndpointNode).starts.Load())
	p.UpdateNodes(nil, initial)
	same, _ := ep.Get("p/a")
	require.Same(t, old, same)
	failed := []option.Endpoint{{Type: "test", Tag: "a", Options: &nodeOptions{Fail: true}}}
	p.UpdateNodes(nil, failed)
	same, _ = ep.Get("p/a")
	require.Same(t, old, same)
	next := []option.Endpoint{{Type: "test", Tag: "a", Options: &nodeOptions{Revision: 2}}}
	p.UpdateNodes(nil, next)
	changed, _ := ep.Get("p/a")
	require.NotSame(t, old, changed)
	require.EqualValues(t, 1, old.(*testEndpointNode).closes.Load())
	require.NoError(t, p.Close())
	require.EqualValues(t, 1, changed.(*testEndpointNode).closes.Load())
	require.NoError(t, scope.Close())
	require.EqualValues(t, 1, changed.(*testEndpointNode).closes.Load())
}

func TestProviderOrdersCrossKindDependenciesAndRejectsCycles(t *testing.T) {
	ctx := context.Background()
	factory := log.NewNOPFactory()
	logger := factory.Logger()
	outRegistry, epRegistry := outbound.NewRegistry(), endpoint.NewRegistry()
	ep := endpoint.NewManager(epRegistry)
	out := outbound.NewManager(outRegistry, ep, "")
	var order []string
	makeNode := func(tag string, opts nodeOptions) *testNode {
		if opts.Detour != "" {
			_, found := out.Outbound(opts.Detour)
			require.True(t, found, "dependency must be installed before %s", tag)
		}
		order = append(order, tag)
		return &testNode{Adapter: outbound.NewAdapterWithDialerOptions("test", tag, []string{"tcp"}, opts.DialerOptions), options: opts}
	}
	outbound.Register[nodeOptions](outRegistry, "test", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, opts nodeOptions) (adapter.Outbound, error) {
		return makeNode(tag, opts), nil
	})
	endpoint.Register[nodeOptions](epRegistry, "test", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, opts nodeOptions) (adapter.Endpoint, error) {
		return &testEndpointNode{testNode: makeNode(tag, opts)}, nil
	})
	p := provider.NewAdapter(ctx, nil, out, ep, factory, logger, "p", "inline", option.ProviderHealthCheckOptions{})
	defer p.Close()
	opts := func(dep string) *nodeOptions { return &nodeOptions{DialerOptions: option.DialerOptions{Detour: dep}} }
	outs := []option.Outbound{{Type: "test", Tag: "last", Options: opts("p/middle")}, {Type: "test", Tag: "first", Options: opts("")}}
	eps := []option.Endpoint{{Type: "test", Tag: "middle", Options: opts("p/first")}}
	require.NoError(t, p.UpdateNodes(outs, eps))
	require.Equal(t, []string{"p/first", "p/middle", "p/last"}, order)
	outs[1].Options = opts("p/last")
	require.ErrorContains(t, p.UpdateNodes(outs, eps), "circular")
	require.Len(t, order, 3, "cycle rejection must not replace existing nodes")
}

func TestProviderDoesNotOverwriteStaticOutboundOrEndpoint(t *testing.T) {
	ctx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
	factory := log.NewNOPFactory()
	logger := factory.Logger()
	outRegistry, epRegistry := outbound.NewRegistry(), endpoint.NewRegistry()
	outbound.Register[nodeOptions](outRegistry, "test", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options nodeOptions) (adapter.Outbound, error) {
		return &testNode{Adapter: outbound.NewAdapter("test", tag, []string{"tcp"}, nil), options: options}, nil
	})
	endpoint.Register[nodeOptions](epRegistry, "test", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options nodeOptions) (adapter.Endpoint, error) {
		return &testEndpointNode{testNode: &testNode{Adapter: outbound.NewAdapter("test", tag, []string{"tcp"}, nil), options: options}}, nil
	})
	epMgr := endpoint.NewManager(epRegistry)
	outMgr := outbound.NewManager(outRegistry, epMgr, "")
	require.NoError(t, outMgr.Create(ctx, nil, logger, "p/static-out", "test", &nodeOptions{Revision: 1}))
	require.NoError(t, epMgr.Create(ctx, nil, logger, "p/static-ep", "test", &nodeOptions{Revision: 1}))
	scope := adapter.NewScope(ctx, logger)
	t.Cleanup(func() { require.NoError(t, scope.Close()) })
	for _, stage := range adapter.ListStartStages {
		require.NoError(t, scope.Start("endpoint", epMgr, stage))
		require.NoError(t, scope.Start("outbound", outMgr, stage))
	}
	staticOut, _ := outMgr.Outbound("p/static-out")
	staticEP, _ := epMgr.Get("p/static-ep")

	p := provider.NewAdapter(ctx, nil, outMgr, epMgr, factory, logger, "p", "inline", option.ProviderHealthCheckOptions{})
	require.NoError(t, p.Start())
	t.Cleanup(func() { require.NoError(t, p.Close()) })

	err := p.UpdateNodes(
		[]option.Outbound{
			{Type: "test", Tag: "static-out", Options: &nodeOptions{Revision: 2}},
			{Type: "test", Tag: "owned", Options: &nodeOptions{Revision: 1}},
		},
		[]option.Endpoint{
			{Type: "test", Tag: "static-ep", Options: &nodeOptions{Revision: 2}},
		},
	)
	require.Error(t, err)
	require.ErrorContains(t, err, "conflicts with existing")

	gotOut, found := outMgr.Outbound("p/static-out")
	require.True(t, found)
	require.Same(t, staticOut, gotOut)
	require.Zero(t, staticOut.(*testNode).closes.Load())

	gotEP, found := epMgr.Get("p/static-ep")
	require.True(t, found)
	require.Same(t, staticEP, gotEP)
	require.Zero(t, staticEP.(*testEndpointNode).closes.Load())

	_, ownedFound := p.Outbound("p/owned")
	require.True(t, ownedFound)
	_, conflictOwned := p.Outbound("p/static-out")
	require.False(t, conflictOwned)

	// Removing everything from provider must leave static objects intact.
	require.NoError(t, p.UpdateNodes(nil, nil))
	gotOut, found = outMgr.Outbound("p/static-out")
	require.True(t, found)
	require.Same(t, staticOut, gotOut)
	gotEP, found = epMgr.Get("p/static-ep")
	require.True(t, found)
	require.Same(t, staticEP, gotEP)
}

func TestProviderCrossKindReplacementFailurePreservesOldNode(t *testing.T) {
	ctx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
	factory := log.NewNOPFactory()
	logger := factory.Logger()
	outRegistry, epRegistry := outbound.NewRegistry(), endpoint.NewRegistry()
	epMgr := endpoint.NewManager(epRegistry)
	outMgr := outbound.NewManager(outRegistry, epMgr, "")
	var switchDependency adapter.Outbound
	outbound.Register[nodeOptions](outRegistry, "test", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options nodeOptions) (adapter.Outbound, error) {
		if options.Detour != "" {
			switchDependency, _ = outMgr.Outbound(options.Detour)
		}
		return &testNode{Adapter: outbound.NewAdapter("test", tag, []string{"tcp"}, nil), options: options}, nil
	})
	endpoint.Register[nodeOptions](epRegistry, "test", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options nodeOptions) (adapter.Endpoint, error) {
		return &testEndpointNode{testNode: &testNode{Adapter: outbound.NewAdapter("test", tag, []string{"tcp"}, nil), options: options}}, nil
	})
	scope := adapter.NewScope(ctx, logger)
	t.Cleanup(func() { require.NoError(t, scope.Close()) })
	for _, stage := range adapter.ListStartStages {
		require.NoError(t, scope.Start("endpoint", epMgr, stage))
		require.NoError(t, scope.Start("outbound", outMgr, stage))
	}
	p := provider.NewAdapter(ctx, nil, outMgr, epMgr, factory, logger, "p", "inline", option.ProviderHealthCheckOptions{})
	require.NoError(t, p.Start())
	t.Cleanup(func() { require.NoError(t, p.Close()) })

	// Start as outbound.
	require.NoError(t, p.UpdateNodes([]option.Outbound{{Type: "test", Tag: "node", Options: &nodeOptions{Revision: 1}}}, nil))
	oldOut, found := outMgr.Outbound("p/node")
	require.True(t, found)

	// Switch outbound -> failing endpoint: old outbound must stay active and unclosed.
	err := p.UpdateNodes(nil, []option.Endpoint{{Type: "test", Tag: "node", Options: &nodeOptions{Revision: 2, Fail: true}}})
	require.Error(t, err)
	retainedOut, found := outMgr.Outbound("p/node")
	require.True(t, found)
	require.Same(t, oldOut, retainedOut)
	require.Zero(t, oldOut.(*testNode).closes.Load())
	require.Len(t, p.Outbounds(), 1)
	require.Same(t, oldOut, p.Outbounds()[0])

	// Switch outbound -> healthy endpoint: new endpoint published, old outbound closed.
	require.NoError(t, p.UpdateNodes(
		[]option.Outbound{{Type: "test", Tag: "dependent", Options: &nodeOptions{DialerOptions: option.DialerOptions{Detour: "p/node"}}}},
		[]option.Endpoint{{Type: "test", Tag: "node", Options: &nodeOptions{Revision: 3}}},
	))
	newEP, found := epMgr.Get("p/node")
	require.True(t, found)
	require.Same(t, newEP, switchDependency)
	require.EqualValues(t, 1, oldOut.(*testNode).closes.Load())
	gotAfterSwitch, found := outMgr.Outbound("p/node")
	require.True(t, found)
	require.Same(t, newEP, gotAfterSwitch)

	// Switch endpoint -> failing outbound: old endpoint must stay active and unclosed.
	err = p.UpdateNodes([]option.Outbound{{Type: "test", Tag: "node", Options: &nodeOptions{Revision: 4, Fail: true}}}, nil)
	require.Error(t, err)
	retainedEP, found := epMgr.Get("p/node")
	require.True(t, found)
	require.Same(t, newEP, retainedEP)
	require.Zero(t, newEP.(*testEndpointNode).closes.Load())
	require.Len(t, p.Outbounds(), 1)
	require.Same(t, newEP, p.Outbounds()[0])
}
