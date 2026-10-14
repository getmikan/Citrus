package config

import (
	"fmt"
	"strings"
)

// chainGroupType is the `type` of a proxy group that is a chain of hops.
const chainGroupType = "chain"

// builtinProxies are the proxies that exist without being configured.
var builtinProxies = map[string]bool{
	"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "COMPATIBLE": true, "PASS": true, "PASS-RULE": true, "GLOBAL": true,
}

// chainGraph is the raw configuration seen as names: proxies, groups and
// providers, so that the chain groups can be wired and checked before
// anything is parsed.
type chainGraph struct {
	proxies   map[string]map[string]any
	groups    map[string]map[string]any
	providers map[string]map[string]any
	// wiredBy remembers the chain that set the dialer-proxy of a proxy or a
	// provider, for the error of a conflict.
	wiredBy map[string]string
}

// expandChains wires the chain groups of the configuration: every hop after
// the first one is dialed through the hop before it, by setting the
// dialer-proxy of the proxies that make the hop up (the proxy itself, the
// members of a group, the proxies of the providers of a group). It reports a
// conflict with a dialer-proxy that is already set and a loop that goes
// through a chain. The configuration without chain groups is left as it is.
func expandChains(cfg *RawConfig) error {
	var chains []map[string]any
	for _, g := range cfg.ProxyGroup {
		if t, _ := g["type"].(string); t == chainGroupType {
			chains = append(chains, g)
		}
	}
	if len(chains) == 0 {
		return nil
	}

	cg := &chainGraph{
		proxies:   make(map[string]map[string]any, len(cfg.Proxy)),
		groups:    make(map[string]map[string]any, len(cfg.ProxyGroup)),
		providers: cfg.ProxyProvider,
		wiredBy:   map[string]string{},
	}
	for _, p := range cfg.Proxy {
		if name, ok := p["name"].(string); ok {
			cg.proxies[name] = p
		}
	}
	for _, g := range cfg.ProxyGroup {
		if name, ok := g["name"].(string); ok {
			cg.groups[name] = g
		}
	}

	for _, c := range chains {
		name, _ := c["name"].(string)
		hops := stringList(c["proxies"])
		if len(hops) < 2 {
			return fmt.Errorf("chain [%s]: needs at least two hops in `proxies`", name)
		}
		for _, key := range []string{"use", "include-all", "include-all-proxies", "include-all-providers", "filter", "exclude-filter", "exclude-type"} {
			if _, ok := c[key]; ok {
				return fmt.Errorf("chain [%s]: `%s` is not supported, list the hops in `proxies`", name, key)
			}
		}
		seen := map[string]bool{}
		for i, hop := range hops {
			if hop == name {
				return fmt.Errorf("chain [%s]: the chain is one of its own hops", name)
			}
			if seen[hop] {
				return fmt.Errorf("chain [%s]: hop [%s] appears twice", name, hop)
			}
			seen[hop] = true
			if !cg.exists(hop) {
				return fmt.Errorf("chain [%s]: hop %d [%s] not found", name, i+1, hop)
			}
		}
	}

	// the loops are looked for on the configuration as it is written, so
	// that the error names what the user wrote; the wiring below only adds
	// the edges hop -> previous hop, checked again afterwards
	for _, c := range chains {
		if err := cg.findLoop(c["name"].(string)); err != nil {
			return err
		}
	}

	for _, c := range chains {
		name := c["name"].(string)
		hops := stringList(c["proxies"])
		for i := 1; i < len(hops); i++ {
			if err := cg.wire(name, i+1, hops[i], hops[i-1], "", map[string]bool{}); err != nil {
				return err
			}
		}
	}

	for _, c := range chains {
		if err := cg.findLoop(c["name"].(string)); err != nil {
			return err
		}
	}
	return nil
}

func (cg *chainGraph) exists(name string) bool {
	_, isProxy := cg.proxies[name]
	_, isGroup := cg.groups[name]
	return isProxy || isGroup || builtinProxies[name]
}

// wire makes `name`, the hop at position pos of the chain or a member of the
// group `parent` of that hop, dial through via.
func (cg *chainGraph) wire(chain string, pos int, name, via, parent string, visiting map[string]bool) error {
	if visiting[name] {
		return nil
	}
	visiting[name] = true

	if p, ok := cg.proxies[name]; ok {
		return cg.setDialerProxy(chain, pos, "proxy", name, p, via)
	}
	g, ok := cg.groups[name]
	if !ok {
		if builtinProxies[name] {
			if parent != "" {
				return fmt.Errorf("chain [%s]: group [%s] (hop %d) contains the built-in [%s], which can not go through [%s]; only the first hop may contain it", chain, parent, pos, name, via)
			}
			return fmt.Errorf("chain [%s]: the built-in [%s] can not be hop %d, only the first hop", chain, name, pos)
		}
		if parent != "" {
			return fmt.Errorf("chain [%s]: member [%s] of group [%s] (hop %d) not found", chain, name, parent, pos)
		}
		return fmt.Errorf("chain [%s]: hop %d [%s] not found", chain, pos, name)
	}

	if t, _ := g["type"].(string); t == chainGroupType {
		// a chain inside a chain: its first hop goes through via
		hops := stringList(g["proxies"])
		if len(hops) == 0 {
			return fmt.Errorf("chain [%s]: chain [%s] has no hops", chain, name)
		}
		return cg.wire(chain, pos, hops[0], via, name, visiting)
	}

	for _, key := range []string{"include-all", "include-all-proxies", "include-all-providers"} {
		if v, _ := g[key].(bool); v {
			return fmt.Errorf("chain [%s]: group [%s] with `%s` can not be hop %d, list its members in `proxies` or `use`", chain, name, key, pos)
		}
	}
	for _, member := range stringList(g["proxies"]) {
		if err := cg.wire(chain, pos, member, via, name, visiting); err != nil {
			return err
		}
	}
	for _, pdName := range stringList(g["use"]) {
		pd, ok := cg.providers[pdName]
		if !ok {
			return fmt.Errorf("chain [%s]: provider [%s] of group [%s] not found", chain, pdName, name)
		}
		if ov, ok := pd["override"].(map[string]any); ok {
			if cur, ok := ov["dialer-proxy"].(string); ok && cur != "" && cur != via {
				return fmt.Errorf("chain [%s]: provider [%s] (in group [%s], hop %d) already has override.dialer-proxy [%s], the chain needs [%s]", chain, pdName, name, pos, cur, via)
			}
		}
		if err := cg.setDialerProxy(chain, pos, "provider", pdName, pd, via); err != nil {
			return err
		}
	}
	return nil
}

func (cg *chainGraph) setDialerProxy(chain string, pos int, kind, name string, mapping map[string]any, via string) error {
	if cur, _ := mapping["dialer-proxy"].(string); cur != "" && cur != via {
		if by, ok := cg.wiredBy[kind+"\x00"+name]; ok {
			return fmt.Errorf("chain [%s]: %s [%s] (hop %d) must go through [%s], but chain [%s] already sends it through [%s]", chain, kind, name, pos, via, by, cur)
		}
		return fmt.Errorf("chain [%s]: %s [%s] (hop %d) already has dialer-proxy [%s], the chain needs [%s]", chain, kind, name, pos, cur, via)
	}
	mapping["dialer-proxy"] = via
	if _, ok := cg.wiredBy[kind+"\x00"+name]; !ok {
		cg.wiredBy[kind+"\x00"+name] = chain
	}
	return nil
}

// edges lists what a name depends on to dial: the dialer-proxy of a proxy,
// the members of a group (and the dialer-proxy of its providers), the hops
// of a chain.
func (cg *chainGraph) edges(name string) []string {
	if p, ok := cg.proxies[name]; ok {
		if dp, _ := p["dialer-proxy"].(string); dp != "" {
			return []string{dp}
		}
		return nil
	}
	g, ok := cg.groups[name]
	if !ok {
		return nil
	}
	out := stringList(g["proxies"])
	for _, pdName := range stringList(g["use"]) {
		pd := cg.providers[pdName]
		if pd == nil {
			continue
		}
		dp, _ := pd["dialer-proxy"].(string)
		if ov, ok := pd["override"].(map[string]any); ok {
			if v, _ := ov["dialer-proxy"].(string); v != "" {
				dp = v
			}
		}
		if dp != "" {
			out = append(out, dp)
		}
	}
	return out
}

// findLoop looks for a loop reachable from the chain.
func (cg *chainGraph) findLoop(start string) error {
	const (
		unseen = iota
		onPath
		done
	)
	state := map[string]int{}
	var path []string
	var visit func(name string) []string
	visit = func(name string) []string {
		switch state[name] {
		case onPath:
			for i, n := range path {
				if n == name {
					return append(append([]string{}, path[i:]...), name)
				}
			}
		case done:
			return nil
		}
		state[name] = onPath
		path = append(path, name)
		for _, next := range cg.edges(name) {
			if loop := visit(next); loop != nil {
				return loop
			}
		}
		path = path[:len(path)-1]
		state[name] = done
		return nil
	}
	if loop := visit(start); loop != nil {
		return fmt.Errorf("chain [%s]: loop detected: %s", start, strings.Join(loop, " -> "))
	}
	return nil
}

func stringList(v any) []string {
	switch l := v.(type) {
	case []string:
		return l
	case []any:
		out := make([]string, 0, len(l))
		for _, e := range l {
			if s, ok := e.(string); ok {
				out = append(out, s)
			} else {
				out = append(out, fmt.Sprint(e))
			}
		}
		return out
	}
	return nil
}
