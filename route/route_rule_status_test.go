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

func TestDisabledRuleFallsThrough(t *testing.T) {
	logger := log.NewNOPFactory().NewLogger("test")

	disabledRule, err := R.NewDefaultRule(context.Background(), logger, option.DefaultRule{
		RuleAction: option.RuleAction{
			Action:       C.RuleActionTypeRoute,
			RouteOptions: option.RouteActionOptions{Outbound: "disabled"},
		},
	})
	require.NoError(t, err)
	disabledRule.ChangeStatus()
	require.True(t, disabledRule.Disabled())

	bypassRule, err := R.NewDefaultRule(context.Background(), logger, option.DefaultRule{
		RuleAction: option.RuleAction{
			Action: C.RuleActionTypeBypass,
		},
	})
	require.NoError(t, err)

	nextRule, err := R.NewDefaultRule(context.Background(), logger, option.DefaultRule{
		RuleAction: option.RuleAction{
			Action:       C.RuleActionTypeRoute,
			RouteOptions: option.RouteActionOptions{Outbound: "next"},
		},
	})
	require.NoError(t, err)

	router := &Router{
		logger: logger,
		rules:  []adapter.Rule{disabledRule, bypassRule, nextRule},
	}

	metadata := adapter.InboundContext{}
	matched, _, _, _, err := router.matchRule(context.Background(), &metadata, nil, nil)
	require.NoError(t, err)
	require.Same(t, bypassRule, matched)
}

func TestDisabledRuleReferenceReachability(t *testing.T) {
	runtime := make([]adapter.Rule, 2)
	logger := log.NewNOPFactory().NewLogger("test")

	disabledRule, err := R.NewDefaultRule(context.Background(), logger, option.DefaultRule{
		RuleAction: option.RuleAction{
			Action:       C.RuleActionTypeRoute,
			RouteOptions: option.RouteActionOptions{Outbound: "disabled"},
		},
	})
	require.NoError(t, err)
	disabledRule.ChangeStatus()
	require.True(t, disabledRule.Disabled())
	runtime[0] = disabledRule

	fallbackRule, err := R.NewDefaultRule(context.Background(), logger, option.DefaultRule{
		RuleAction: option.RuleAction{
			Action:       C.RuleActionTypeRoute,
			RouteOptions: option.RouteActionOptions{Outbound: "fallback"},
		},
	})
	require.NoError(t, err)
	runtime[1] = fallbackRule

	routeOptions := []option.Rule{
		{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{RuleAction: option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: "disabled"}}}},
		{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultRule{RuleAction: option.RuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.RouteActionOptions{Outbound: "fallback"}}}},
	}
	dnsOptions := []option.DNSRule{
		{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultDNSRule{DNSRuleAction: option.DNSRuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.DNSRouteActionOptions{Server: "disabled"}}}},
		{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultDNSRule{DNSRuleAction: option.DNSRuleAction{Action: C.RuleActionTypeRoute, RouteOptions: option.DNSRouteActionOptions{Server: "fallback"}}}},
	}

	var outbounds, transports []string
	require.True(t, collectRuleReferences(enabledRuleOptions(routeOptions, runtime), "", &outbounds, &transports))
	require.Equal(t, []string{"fallback"}, outbounds)

	transports = nil
	require.True(t, collectDNSRuleReferences(enabledRuleOptions(dnsOptions, runtime), "", &transports))
	require.Equal(t, []string{"fallback"}, transports)

	runtime[1].ChangeStatus()
	require.True(t, runtime[1].Disabled())
	outbounds = nil
	transports = nil
	require.False(t, collectRuleReferences(enabledRuleOptions(routeOptions, runtime), "", &outbounds, &transports))
	require.False(t, collectDNSRuleReferences(enabledRuleOptions(dnsOptions, runtime), "", &transports))

	runtime[0].ChangeStatus()
	require.False(t, runtime[0].Disabled())
	outbounds = nil
	transports = nil
	require.True(t, collectRuleReferences(enabledRuleOptions(routeOptions, runtime), "", &outbounds, &transports))
	require.Equal(t, []string{"disabled"}, outbounds)
}
