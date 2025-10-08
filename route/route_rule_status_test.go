package route

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"

	"github.com/stretchr/testify/require"
)

func TestDisabledRuleFallsThroughPreMatchAndMatch(t *testing.T) {
	ctx := context.Background()
	logger := log.NewNOPFactory().NewLogger("test")
	newRule := func(action option.RuleAction) adapter.Rule {
		rule, err := R.NewDefaultRule(ctx, logger, option.DefaultRule{RuleAction: action})
		require.NoError(t, err)
		return rule
	}
	first := newRule(option.RuleAction{Action: C.RuleActionTypeReject, RejectOptions: option.RejectActionOptions{Method: C.RuleActionRejectMethodDefault}})
	bypass := newRule(option.RuleAction{Action: C.RuleActionTypeBypass})
	next := newRule(option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: "next"}})
	router := &Router{ctx: ctx, logger: logger, rules: []adapter.Rule{first, bypass, next}}
	metadata := adapter.InboundContext{Domain: "example.com"}

	first.ChangeStatus()
	require.True(t, first.Disabled())
	require.Equal(t, adapter.PreMatchBypass, router.PreMatch(metadata, nil).Action)
	matched, index, _, _, err := router.matchRule(ctx, &metadata, nil, nil)
	require.NoError(t, err)
	require.Same(t, next, matched)
	require.Equal(t, 2, index)

	first.ChangeStatus()
	require.False(t, first.Disabled())
	require.Equal(t, adapter.PreMatchReject, router.PreMatch(metadata, nil).Action)
	matched, index, _, _, err = router.matchRule(ctx, &metadata, nil, nil)
	require.NoError(t, err)
	require.Same(t, first, matched)
	require.Zero(t, index)
}

func TestDisabledRuleReferenceReachability(t *testing.T) {
	ctx := context.Background()
	logger := log.NewNOPFactory().NewLogger("test")
	var runtime []adapter.Rule
	var routeOptions []option.Rule
	var dnsOptions []option.DNSRule
	for _, tag := range []string{"first", "fallback"} {
		rule, err := R.NewDefaultRule(ctx, logger, option.DefaultRule{RuleAction: option.RuleAction{
			Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: tag},
		}})
		require.NoError(t, err)
		runtime = append(runtime, rule)
		routeOptions = append(routeOptions, option.Rule{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{
			RuleAction: option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: tag}},
		}})
		dnsOptions = append(dnsOptions, option.DNSRule{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultDNSRule{
			DNSRuleAction: option.DNSRuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.DNSRouteActionOptions{Server: tag}},
		}})
	}

	check := func(expected string, shadowed bool) {
		var outbounds, routeTransports, dnsTransports []string
		require.Equal(t, shadowed, collectRuleReferences(enabledRuleOptions(routeOptions, runtime), "", &outbounds, &routeTransports))
		require.Equal(t, shadowed, collectDNSRuleReferences(enabledRuleOptions(dnsOptions, runtime), "", &dnsTransports))
		require.Empty(t, routeTransports)
		if expected == "" {
			require.Empty(t, outbounds)
			require.Empty(t, dnsTransports)
		} else {
			require.Equal(t, []string{expected}, outbounds)
			require.Equal(t, []string{expected}, dnsTransports)
		}
	}

	check("first", true)
	runtime[0].ChangeStatus()
	check("fallback", true)
	runtime[1].ChangeStatus()
	check("", false)
	runtime[0].ChangeStatus()
	check("first", true)

	require.Equal(t, routeOptions, enabledRuleOptions(routeOptions, runtime[:1]))
	require.Equal(t, dnsOptions, enabledRuleOptions(dnsOptions, runtime[:1]))
}
