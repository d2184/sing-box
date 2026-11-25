package parser

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

var subscriptionParsers = []func(ctx context.Context, content string) ([]option.Outbound, []option.Endpoint, error){
	ParseBoxSubscription,
	ParseClashSubscription,
	ParseSIP008Subscription,
	ParseRawSubscription,
}

func ParseSubscription(ctx context.Context, content string) ([]option.Outbound, []option.Endpoint, error) {
	var pErr error
	for _, parser := range subscriptionParsers {
		outbounds, endpoints, err := parser(ctx, content)
		if len(outbounds) > 0 || len(endpoints) > 0 {
			return outbounds, endpoints, nil
		}
		pErr = E.Errors(pErr, err)
	}
	return nil, nil, E.Cause(pErr, "no servers found")
}

// ApplyOverrideDialer modifies freshly parsed node options in place.
func ApplyOverrideDialer(outbounds []option.Outbound, endpoints []option.Endpoint, overrideOptions *option.OverrideDialerOptions, provider adapter.Provider) {
	prefix := provider.Tag()
	if prefix != "" {
		prefix += "/"
	}
	tags := make(map[string]bool, len(outbounds)+len(endpoints))
	for _, outbound := range outbounds {
		tags[prefix+outbound.Tag] = true
	}
	for _, endpoint := range endpoints {
		tags[prefix+endpoint.Tag] = true
	}
	isInternal := func(tag string) bool {
		if tags[tag] {
			return true
		}
		_, found := provider.Outbound(tag)
		return found
	}
	apply := func(wrapper option.DialerOptionsWrapper) {
		options := wrapper.TakeDialerOptions()
		if detour := options.Detour; detour != "" {
			switch qualifiedTag := prefix + detour; {
			case isInternal(qualifiedTag):
				options.Detour = qualifiedTag
			case isInternal(detour):
				// The subscription already uses the provider-qualified tag.
			default:
				options.Detour = ""
			}
		}
		wrapper.ReplaceDialerOptions(overrideDialerOption(options, overrideOptions))
	}
	for _, outbound := range outbounds {
		switch outbound.Type {
		case C.TypeHTTP, C.TypeSOCKS, C.TypeTUIC, C.TypeVMess, C.TypeVLESS, C.TypeTrojan,
			C.TypeHysteria, C.TypeShadowTLS, C.TypeHysteria2, C.TypeAnyTLS, C.TypeShadowsocks, C.TypeSSH, C.TypeSnell, C.TypeNaive:
			apply(outbound.Options.(option.DialerOptionsWrapper))
		}
	}
	for _, endpoint := range endpoints {
		switch endpoint.Type {
		case C.TypeWireGuard, C.TypeTailscale:
			apply(endpoint.Options.(option.DialerOptionsWrapper))
		}
	}
}

func overrideDialerOption(options option.DialerOptions, overrideDialerOptions *option.OverrideDialerOptions) option.DialerOptions {
	if overrideDialerOptions == nil || *overrideDialerOptions == (option.OverrideDialerOptions{}) {
		return options
	}
	if overrideDialerOptions.Detour != nil && options.Detour == "" {
		options.Detour = *overrideDialerOptions.Detour
	}
	if overrideDialerOptions.BindInterface != nil {
		options.BindInterface = *overrideDialerOptions.BindInterface
	}
	if overrideDialerOptions.Inet4BindAddress != nil {
		options.Inet4BindAddress = overrideDialerOptions.Inet4BindAddress
	}
	if overrideDialerOptions.Inet6BindAddress != nil {
		options.Inet6BindAddress = overrideDialerOptions.Inet6BindAddress
	}
	if overrideDialerOptions.ProtectPath != nil {
		options.ProtectPath = *overrideDialerOptions.ProtectPath
	}
	if overrideDialerOptions.RoutingMark != nil {
		options.RoutingMark = *overrideDialerOptions.RoutingMark
	}
	if overrideDialerOptions.ReuseAddr != nil {
		options.ReuseAddr = *overrideDialerOptions.ReuseAddr
	}
	if overrideDialerOptions.ConnectTimeout != nil {
		options.ConnectTimeout = *overrideDialerOptions.ConnectTimeout
	}
	if overrideDialerOptions.TCPFastOpen != nil {
		options.TCPFastOpen = *overrideDialerOptions.TCPFastOpen
	}
	if overrideDialerOptions.TCPMultiPath != nil {
		options.TCPMultiPath = *overrideDialerOptions.TCPMultiPath
	}
	if overrideDialerOptions.UDPFragment != nil {
		options.UDPFragment = overrideDialerOptions.UDPFragment
	}
	if overrideDialerOptions.DomainResolver != nil {
		options.DomainResolver = overrideDialerOptions.DomainResolver
	}
	if overrideDialerOptions.NetworkStrategy != nil {
		options.NetworkStrategy = overrideDialerOptions.NetworkStrategy
	}
	if overrideDialerOptions.NetworkType != nil {
		options.NetworkType = *overrideDialerOptions.NetworkType
	}
	if overrideDialerOptions.FallbackNetworkType != nil {
		options.FallbackNetworkType = *overrideDialerOptions.FallbackNetworkType
	}
	if overrideDialerOptions.FallbackDelay != nil {
		options.FallbackDelay = *overrideDialerOptions.FallbackDelay
	}

	//nolint:staticcheck
	if overrideDialerOptions.DomainStrategy != nil {
		options.DomainStrategy = *overrideDialerOptions.DomainStrategy
	}
	return options
}
