package parser

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

func TestOverrideDialerOptionPreservesDomainResolver(t *testing.T) {
	resolver := &option.DomainResolveOptions{Server: "dns-local"}
	timeout := badoption.Duration(5 * time.Second)
	var base option.DialerOptions
	base.DomainResolver = resolver
	got := overrideDialerOption(base, &option.OverrideDialerOptions{
		ConnectTimeout: &timeout,
	})
	require.Equal(t, resolver, got.DomainResolver)
	require.Equal(t, timeout, got.ConnectTimeout)

	newResolver := &option.DomainResolveOptions{Server: "dns-override"}
	got = overrideDialerOption(base, &option.OverrideDialerOptions{
		DomainResolver: newResolver,
	})
	require.Equal(t, newResolver, got.DomainResolver)
}

func TestParseBoxSubscriptionMalformedInputDoesNotPanic(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
		errPart string
	}{
		{"outbounds not array", `{"outbounds":"bad"}`, "outbounds must be an array"},
		{"outbound element null", `{"outbounds":[null]}`, "outbounds[0] must be an object"},
		{"outbound element scalar", `{"outbounds":[123]}`, "outbounds[0] must be an object"},
		{"outbound missing type", `{"outbounds":[{"tag":"a"}]}`, "missing type in outbounds[0]"},
		{"outbound non-string type", `{"outbounds":[{"type":123}]}`, "outbounds[0].type must be a string"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				_, _, err := ParseBoxSubscription(context.Background(), tc.payload)
				require.ErrorContains(t, err, tc.errPart)
			})
		})
	}
}
