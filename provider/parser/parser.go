package parser

import (
	"context"
	"reflect"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
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
func ApplyOverrideDialer(outbounds []option.Outbound, endpoints []option.Endpoint, overrideDialerOptions *option.OverrideDialerOptions, providerTag string) ([]option.Outbound, []option.Endpoint) {
	tags := providerTags(outbounds, endpoints)
	return overrideOutbounds(outbounds, overrideDialerOptions, tags, providerTag),
		overrideEndpoints(endpoints, overrideDialerOptions, tags, providerTag)
}

func providerTags(outbounds []option.Outbound, endpoints []option.Endpoint) []string {
	tags := make([]string, 0, len(outbounds)+len(endpoints))
	for _, outbound := range outbounds {
		tags = append(tags, outbound.Tag)
	}
	for _, endpoint := range endpoints {
		tags = append(tags, endpoint.Tag)
	}
	return tags
}

func overrideOutbounds(outbounds []option.Outbound, overrideDialerOptions *option.OverrideDialerOptions, tags []string, providerTag string) []option.Outbound {
	var parsedOutbounds []option.Outbound
	for _, outbound := range outbounds {
		switch outbound.Type {
		case C.TypeHTTP, C.TypeSOCKS, C.TypeTUIC, C.TypeVMess, C.TypeVLESS, C.TypeTrojan,
			C.TypeHysteria, C.TypeShadowTLS, C.TypeHysteria2, C.TypeAnyTLS, C.TypeShadowsocks, C.TypeSnell, C.TypeNaive:
			options := outbound.Options.(option.DialerOptionsWrapper)
			options.ReplaceDialerOptions(overrideDialerOption(options.TakeDialerOptions(), overrideDialerOptions, tags, providerTag))
		}
		parsedOutbounds = append(parsedOutbounds, outbound)
	}
	return parsedOutbounds
}

func overrideEndpoints(endpoints []option.Endpoint, overrideDialerOptions *option.OverrideDialerOptions, tags []string, providerTag string) []option.Endpoint {
	if len(endpoints) == 0 {
		return nil
	}
	var parsedEndpoints []option.Endpoint
	for _, ep := range endpoints {
		switch ep.Type {
		case C.TypeWireGuard:
			options := ep.Options.(*option.WireGuardEndpointOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideDialerOptions, tags, providerTag)
			ep.Options = options
		case C.TypeTailscale:
			options := ep.Options.(*option.TailscaleEndpointOptions)
			options.DialerOptions = overrideDialerOption(options.DialerOptions, overrideDialerOptions, tags, providerTag)
			ep.Options = options
		}
		parsedEndpoints = append(parsedEndpoints, ep)
	}
	return parsedEndpoints
}

func overrideDialerOption(options option.DialerOptions, overrideDialerOptions *option.OverrideDialerOptions, tags []string, providerTag string) option.DialerOptions {
	if options.Detour != "" {
		if common.Any(tags, func(tag string) bool {
			return options.Detour == tag
		}) {
			if providerTag != "" {
				options.Detour = providerTag + "/" + options.Detour
			}
		} else if providerTag == "" || !common.Any(tags, func(tag string) bool {
			return options.Detour == providerTag+"/"+tag
		}) {
			options.Detour = ""
		}
	}
	var defaultOptions option.OverrideDialerOptions
	if overrideDialerOptions == nil || reflect.DeepEqual(*overrideDialerOptions, defaultOptions) {
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
