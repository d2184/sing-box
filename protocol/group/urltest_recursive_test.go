package group

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	adapterOutbound "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/observable"

	"github.com/stretchr/testify/require"
)

func TestURLTestDeduplicatesSameLeafAndURLAcrossNestedGroups(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	leaf := &recursiveURLTestOutbound{tag: "leaf"}
	manager := &recursiveURLTestOutboundManager{outbounds: make(map[string]adapter.Outbound)}
	history := urltest.NewHistoryStorage()
	firstGroup := newURLTestForRecursiveTest("first", server.URL, manager, history, leaf)
	secondGroup := newURLTestForRecursiveTest("second", server.URL, manager, history, leaf)
	manager.outbounds[leaf.tag] = leaf
	manager.outbounds[firstGroup.Tag()] = firstGroup
	manager.outbounds[secondGroup.Tag()] = secondGroup

	result := URLTestOutbounds(context.Background(), manager, history, log.NewNOPFactory().Logger(), []adapter.Outbound{firstGroup, secondGroup}, "", time.Hour, true)

	require.EqualValues(t, 1, leaf.dialCount.Load())
	require.EqualValues(t, 1, requests.Load())
	require.Contains(t, result, leaf.tag)
	require.Contains(t, result, firstGroup.Tag())
	require.Contains(t, result, secondGroup.Tag())
}

func TestURLTestDoesNotDeduplicateDifferentURLs(t *testing.T) {
	var firstRequests atomic.Int32
	firstServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		firstRequests.Add(1)
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer firstServer.Close()
	var secondRequests atomic.Int32
	secondServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		secondRequests.Add(1)
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer secondServer.Close()

	leaf := &recursiveURLTestOutbound{tag: "leaf"}
	manager := &recursiveURLTestOutboundManager{outbounds: make(map[string]adapter.Outbound)}
	history := urltest.NewHistoryStorage()
	firstGroup := newURLTestForRecursiveTest("first", firstServer.URL, manager, history, leaf)
	secondGroup := newURLTestForRecursiveTest("second", secondServer.URL, manager, history, leaf)
	manager.outbounds[leaf.tag] = leaf
	manager.outbounds[firstGroup.Tag()] = firstGroup
	manager.outbounds[secondGroup.Tag()] = secondGroup

	URLTestOutbounds(context.Background(), manager, history, log.NewNOPFactory().Logger(), []adapter.Outbound{firstGroup, secondGroup}, "", time.Hour, true)

	require.EqualValues(t, 2, leaf.dialCount.Load())
	require.EqualValues(t, 1, firstRequests.Load())
	require.EqualValues(t, 1, secondRequests.Load())
}

func TestURLTestReusedResultDoesNotUpdateHistory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	for _, test := range []struct {
		name string
		link string
	}{
		{name: "success", link: server.URL},
		{name: "failure", link: "://invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, _ := urlTestSessionFromContext(context.Background())
			leaf := &recursiveURLTestOutbound{tag: "leaf"}
			history := urltest.NewHistoryStorage()
			logger := log.NewNOPFactory().Logger()
			outbounds := []adapter.Outbound{leaf}
			initial := &adapter.URLTestHistory{Time: time.Now(), Delay: 123}
			history.StoreURLTestHistory(leaf.tag, initial)

			first := URLTestOutbounds(ctx, nil, history, logger, outbounds, test.link, 0, true)
			if test.name == "success" {
				require.Contains(t, first, leaf.tag)
				require.NotSame(t, initial, history.LoadURLTestHistory(leaf.tag))
			} else {
				require.Empty(t, first)
				require.Nil(t, history.LoadURLTestHistory(leaf.tag))
			}
			updated := &adapter.URLTestHistory{Time: time.Now(), Delay: 456}
			history.StoreURLTestHistory(leaf.tag, updated)
			second := URLTestOutbounds(ctx, nil, history, logger, outbounds, test.link, 0, true)
			require.Equal(t, first, second)
			require.Same(t, updated, history.LoadURLTestHistory(leaf.tag))
		})
	}
}

func TestURLTestConcurrentReusedResultUpdatesHistoryOnce(t *testing.T) {
	for _, test := range []struct {
		name    string
		failure bool
	}{
		{name: "success"},
		{name: "failure", failure: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()

			started := make(chan struct{})
			release := make(chan struct{})
			leaf := &recursiveURLTestOutbound{tag: "leaf", dial: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
				select {
				case started <- struct{}{}:
				default:
				}
				select {
				case <-release:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				if test.failure {
					return nil, errors.New("dial failed")
				}
				return (&net.Dialer{}).DialContext(ctx, network, destination.String())
			}}
			history := urltest.NewHistoryStorage()
			history.StoreURLTestHistory(leaf.tag, &adapter.URLTestHistory{Time: time.Now(), Delay: 123})
			subscriber := observable.NewSubscriber[struct{}](16)
			history.AddUpdateHook(subscriber)
			notifications, _ := subscriber.Subscription()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ctx, _ = urlTestSessionFromContext(ctx)
			const callers = 5
			results := make(chan map[string]uint16, callers)
			invoke := func() {
				results <- URLTestOutbounds(ctx, nil, history, log.NewNOPFactory().Logger(), []adapter.Outbound{leaf}, server.URL, 0, true)
			}
			go invoke()
			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal("test did not start")
			}
			ready := make(chan struct{}, callers-1)
			for range callers - 1 {
				go func() {
					ready <- struct{}{}
					invoke()
				}()
			}
			for range callers - 1 {
				<-ready
			}
			close(release)
			for range callers {
				select {
				case result := <-results:
					if test.failure {
						require.Empty(t, result)
					} else {
						require.Contains(t, result, leaf.tag)
					}
				case <-ctx.Done():
					t.Fatal("test did not finish")
				}
			}
			require.EqualValues(t, 1, leaf.dialCount.Load())
			require.Len(t, notifications, 1)
			if test.failure {
				require.Nil(t, history.LoadURLTestHistory(leaf.tag))
			} else {
				require.NotNil(t, history.LoadURLTestHistory(leaf.tag))
			}
		})
	}
}

func TestURLTestCancellationPreservesHistory(t *testing.T) {
	started := make(chan struct{})
	leaf := &recursiveURLTestOutbound{tag: "leaf", dial: func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	history := urltest.NewHistoryStorage()
	initial := &adapter.URLTestHistory{Time: time.Now(), Delay: 123}
	history.StoreURLTestHistory(leaf.tag, initial)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		URLTestOutbounds(ctx, nil, history, log.NewNOPFactory().Logger(), []adapter.Outbound{leaf}, "http://example.com", 0, true)
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("test did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("test did not stop after cancellation")
	}
	require.Same(t, initial, history.LoadURLTestHistory(leaf.tag))
}

func TestURLTestSelectionKeepsCurrentWithinTolerance(t *testing.T) {
	current := &recursiveURLTestOutbound{tag: "current"}
	candidate := &recursiveURLTestOutbound{tag: "candidate"}
	manager := &recursiveURLTestOutboundManager{outbounds: map[string]adapter.Outbound{
		current.tag:   current,
		candidate.tag: candidate,
	}}
	history := urltest.NewHistoryStorage()
	history.StoreURLTestHistory(current.tag, &adapter.URLTestHistory{Time: time.Now(), Delay: 100})
	history.StoreURLTestHistory(candidate.tag, &adapter.URLTestHistory{Time: time.Now(), Delay: 60})
	group := &URLTestGroup{
		outbound:  manager,
		outbounds: []adapter.Outbound{current, candidate},
		history:   history,
		tolerance: 50,
	}
	group.selectedOutboundTCP.Store(current)

	selected, available := group.Select(N.NetworkTCP)
	require.True(t, available)
	require.Same(t, current, selected)

	history.StoreURLTestHistory(candidate.tag, &adapter.URLTestHistory{Time: time.Now(), Delay: 49})
	selected, available = group.Select(N.NetworkTCP)
	require.True(t, available)
	require.Same(t, candidate, selected)
}

type recursiveURLTestOutbound struct {
	adapter.Outbound
	tag       string
	dialCount atomic.Int32
	dial      func(context.Context, string, M.Socksaddr) (net.Conn, error)
}

func (o *recursiveURLTestOutbound) Tag() string {
	return o.tag
}

func (o *recursiveURLTestOutbound) Network() []string {
	return []string{N.NetworkTCP, N.NetworkUDP}
}

func (o *recursiveURLTestOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	o.dialCount.Add(1)
	if o.dial != nil {
		return o.dial(ctx, network, destination)
	}
	return (&net.Dialer{}).DialContext(ctx, network, destination.String())
}

type recursiveURLTestOutboundManager struct {
	adapter.OutboundManager
	outbounds map[string]adapter.Outbound
}

func (m *recursiveURLTestOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := m.outbounds[tag]
	return outbound, loaded
}

func newURLTestForRecursiveTest(tag string, link string, manager adapter.OutboundManager, history *urltest.HistoryStorage, outbounds ...adapter.Outbound) *URLTest {
	memberTags := make([]string, 0, len(outbounds))
	for _, member := range outbounds {
		memberTags = append(memberTags, member.Tag())
	}
	group := &URLTestGroup{
		ctx:       context.Background(),
		outbound:  manager,
		logger:    log.NewNOPFactory().Logger(),
		outbounds: outbounds,
		link:      link,
		interval:  time.Hour,
		history:   history,
	}
	return &URLTest{
		Adapter: adapterOutbound.NewAdapter(C.TypeURLTest, tag, []string{N.NetworkTCP, N.NetworkUDP}, memberTags),
		group:   group,
	}
}
