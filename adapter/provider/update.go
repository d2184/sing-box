package provider

import (
	"reflect"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

type nodeConfig struct {
	kind      string
	sourceTag string
	options   any
	endpoint  bool
}

type updateNode struct {
	nodeConfig
	tag          string
	current      adapter.Outbound
	dependencies []string
}

// UpdateNodes orders outbounds and endpoints together, so a subscription can
// introduce a detour and its users in either order without restarting them.
func (a *Adapter) UpdateNodes(outOpts []option.Outbound, epOpts []option.Endpoint) error {
	outTags, epTags := a.resolveOutboundTags(outOpts), a.resolveEndpointTags(epOpts)
	nodes := make(map[string]updateNode, len(outOpts)+len(epOpts))
	tags := append(append([]string(nil), outTags...), epTags...)
	for i, opt := range outOpts {
		tag := outTags[i]
		nodes[tag] = updateNode{tag: tag, nodeConfig: nodeConfig{kind: opt.Type, sourceTag: opt.Tag, options: opt.Options}}
	}
	for i, opt := range epOpts {
		tag := epTags[i]
		if _, found := nodes[tag]; found {
			return E.New("duplicate provider node tag: ", tag)
		}
		nodes[tag] = updateNode{tag: tag, nodeConfig: nodeConfig{kind: opt.Type, sourceTag: opt.Tag, options: opt.Options, endpoint: true}}
	}
	unlock := a.outbound.LockProviderUpdate()
	defer unlock()
	if err := a.ctx.Err(); err != nil {
		return err
	}
	a.outboundsAccess.RLock()
	previousOutbounds, previousEndpoints := a.outbounds, a.endpoints
	previousOutByTag, previousEPByTag := a.outboundsByTag, a.endpointsByTag
	a.outboundsAccess.RUnlock()
	for _, tag := range tags {
		outbound, _ := a.outbound.Outbound(tag)
		var endpoint adapter.Endpoint
		if a.endpoint != nil {
			endpoint, _ = a.endpoint.Get(tag)
		}
		if (outbound != nil && outbound != previousOutByTag[tag] && outbound != previousEPByTag[tag]) ||
			(endpoint != nil && endpoint != previousEPByTag[tag]) {
			return E.New("provider node tag conflict: ", tag)
		}
		node := nodes[tag]
		if node.endpoint {
			node.current = endpoint
		} else if outbound == previousOutByTag[tag] {
			node.current = outbound
		}
		nodes[tag] = node
	}
	ordered, err := a.orderNodes(nodes, tags)
	if err != nil {
		return err
	}
	outByTag, epByTag := make(map[string]adapter.Outbound), make(map[string]adapter.Outbound)
	failed := make(map[string]bool)
	var updateErrors []error
applyNodes:
	for _, node := range ordered {
		for _, dependency := range node.dependencies {
			if failed[dependency] {
				failed[node.tag] = true
				updateErrors = append(updateErrors, E.New(node.tag, ": provider dependency failed: ", dependency))
				continue applyNodes
			}
		}
		current := node.current
		if current == nil || !reflect.DeepEqual(node.nodeConfig, a.appliedOptions[node.tag]) {
			ctx := adapter.WithContext(a.ctx, &adapter.InboundContext{Outbound: node.tag})
			var replaceErr error
			if node.endpoint {
				logger := a.logFactory.NewLogger("endpoint/" + node.kind + "[" + node.tag + "]")
				current, replaceErr = a.endpoint.Replace(ctx, a.router, logger, node.tag, node.kind, node.options, node.current)
			} else {
				logger := a.logFactory.NewLogger("outbound/" + node.kind + "[" + node.tag + "]")
				current, replaceErr = a.outbound.Replace(ctx, a.router, logger, node.tag, node.kind, node.options, node.current)
			}
			if replaceErr != nil {
				updateErrors = append(updateErrors, E.Cause(replaceErr, node.tag))
				failed[node.tag] = true
				continue
			}
			// Remove the old kind before dependent nodes look up this tag.
			ownedOut, ownedEP := previousOutByTag[node.tag], previousEPByTag[node.tag]
			if node.endpoint && ownedOut != nil {
				if err := a.outbound.Remove(ownedOut); err != nil {
					a.logger.Error(err, "close outbound [", node.tag, "]")
				}
			} else if !node.endpoint && ownedEP != nil {
				if err := a.endpoint.Remove(ownedEP); err != nil {
					a.logger.Error(err, "close endpoint [", node.tag, "]")
				}
			}
			a.appliedOptions[node.tag] = node.nodeConfig
		}
		if node.endpoint {
			epByTag[node.tag] = current
		} else {
			outByTag[node.tag] = current
		}
	}
	var retainPrevious func(tag string, referencedBy string)
	retainPrevious = func(tag string, referencedBy string) {
		if outByTag[tag] != nil || epByTag[tag] != nil {
			return
		}
		previous := previousOutByTag[tag]
		if previous != nil {
			outByTag[tag] = previous
		} else if previous = previousEPByTag[tag]; previous != nil {
			epByTag[tag] = previous
		} else {
			return
		}
		if _, requested := nodes[tag]; !requested {
			updateErrors = append(updateErrors, E.New("cannot remove provider node [", tag, "]: still referenced by previous instance of [", referencedBy, "]"))
		}
		for _, dependency := range previous.Dependencies() {
			retainPrevious(dependency, tag)
		}
		if referrer, ok := previous.(adapter.Referrer); ok {
			references, _ := referrer.References()
			for _, reference := range references {
				retainPrevious(reference, tag)
			}
		}
	}
	for _, tag := range tags {
		if failed[tag] {
			retainPrevious(tag, "")
		}
	}
	outbounds := a.reconcileNodes(outTags, previousOutbounds, outByTag, epByTag, a.outbound.Remove)
	var endpoints []adapter.Outbound
	if a.endpoint != nil {
		endpoints = a.reconcileNodes(epTags, previousEndpoints, epByTag, outByTag, a.endpoint.Remove)
	}
	a.outboundsAccess.Lock()
	a.outbounds, a.outboundsByTag = outbounds, outByTag
	a.endpoints, a.endpointsByTag = endpoints, epByTag
	a.outboundsAccess.Unlock()
	for tag := range a.appliedOptions {
		if outByTag[tag] == nil && epByTag[tag] == nil {
			delete(a.appliedOptions, tag)
		}
	}
	if a.enabled && a.history != nil {
		a.run(func() { a.HealthCheck(a.ctx) })
	}
	return E.Errors(updateErrors...)
}

func (a *Adapter) orderNodes(nodes map[string]updateNode, tags []string) ([]updateNode, error) {
	ordered := make([]updateNode, 0, len(nodes))
	visiting, visited := make(map[string]bool), make(map[string]bool)
	var visit func(string) error
	visit = func(tag string) error {
		if visited[tag] {
			return nil
		}
		if visiting[tag] {
			return E.New("circular provider dependency: ", tag)
		}
		visiting[tag] = true
		node := nodes[tag]
		if opts, ok := node.options.(option.DialerOptionsWrapper); ok {
			if detour := opts.TakeDialerOptions().Detour; detour != "" {
				node.dependencies = append(node.dependencies, detour)
			}
		}
		switch opts := node.options.(type) {
		case *option.SelectorOutboundOptions:
			node.dependencies = append(node.dependencies, opts.Outbounds...)
		case *option.URLTestOutboundOptions:
			node.dependencies = append(node.dependencies, opts.Outbounds...)
		}
		for _, dependency := range node.dependencies {
			if _, internal := nodes[dependency]; internal {
				if err := visit(dependency); err != nil {
					return err
				}
				continue
			}
			if _, found := a.outbound.Outbound(dependency); !found {
				return E.New("provider dependency not found: ", dependency, " (referenced by ", tag, ")")
			}
			if _, owned := a.appliedOptions[dependency]; owned {
				return E.New("cannot remove provider node [", dependency, "]: still referenced by [", tag, "]")
			}
		}
		visiting[tag] = false
		visited[tag] = true
		ordered = append(ordered, node)
		return nil
	}
	for _, tag := range tags {
		if err := visit(tag); err != nil {
			return nil, err
		}
	}
	return ordered, nil
}

func (a *Adapter) reconcileNodes(tags []string, previous []adapter.Outbound, selected, switched map[string]adapter.Outbound, remove func(adapter.Outbound) error) []adapter.Outbound {
	ordered := make([]adapter.Outbound, 0, len(selected))
	listed := make(map[string]bool, len(tags))
	for _, tag := range tags {
		if node := selected[tag]; node != nil {
			ordered = append(ordered, node)
			listed[tag] = true
		}
	}
	for _, old := range previous {
		tag := old.Tag()
		if node := selected[tag]; node == nil {
			if switched[tag] == nil {
				if err := remove(old); err != nil {
					a.logger.Error(err, "close provider node [", tag, "]")
				}
			}
		} else if !listed[tag] {
			ordered = append(ordered, node)
		}
	}
	return ordered
}
