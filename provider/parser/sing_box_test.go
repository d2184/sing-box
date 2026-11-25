package parser

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func TestParseBoxSubscriptionInvalidOutbounds(test *testing.T) {
	for _, testCase := range []struct {
		name    string
		content string
		wantErr string
	}{
		{"non-array field", `{"outbounds":{}}`, "outbounds must be an array"},
		{"non-object entry", `{"outbounds":[{"type":"direct"},null]}`, "outbounds[1] must be an object"},
		{"missing type", `{"outbounds":[{}]}`, "missing type in outbounds[0]"},
		{"non-string type", `{"outbounds":[{"type":1}]}`, "outbounds[0].type must be a string"},
	} {
		test.Run(testCase.name, func(subtest *testing.T) {
			_, _, err := ParseBoxSubscription(context.Background(), testCase.content)
			require.ErrorContains(subtest, err, testCase.wantErr)
		})
	}
}

func TestParseBoxSubscriptionNullOutbounds(test *testing.T) {
	_, _, err := ParseBoxSubscription(context.Background(), `{"outbounds":null}`)
	require.EqualError(test, err, "no servers found")
}

func TestParseBoxSubscriptionFiltersNonProxyOutbounds(test *testing.T) {
	registry := outbound.NewRegistry()
	outbound.Register[option.SOCKSOutboundOptions](registry, C.TypeSOCKS, nil)
	ctx := service.ContextWith[option.OutboundOptionsRegistry](context.Background(), registry)

	outbounds, _, err := ParseBoxSubscription(ctx, `{"outbounds":[
		{"type":"direct"},
		{"type":"block"},
		{"type":"dns"},
		{"type":"selector"},
		{"type":"urltest"},
		{"type":"socks","tag":"proxy","server":"example.com","server_port":1080}
	]}`)
	require.NoError(test, err)
	require.Len(test, outbounds, 1)
	require.Equal(test, "proxy", outbounds[0].Tag)
}
