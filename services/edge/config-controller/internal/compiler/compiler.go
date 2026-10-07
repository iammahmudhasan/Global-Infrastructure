package compiler

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/store"
)

// EnvoyConfig represents the top-level Envoy v3 bootstrap / static configuration.
type EnvoyConfig struct {
	Admin           Admin           `json:"admin"`
	StaticResources StaticResources `json:"static_resources"`
}

type Admin struct {
	Address Address `json:"address"`
}

type StaticResources struct {
	Listeners []Listener `json:"listeners"`
	Clusters  []Cluster  `json:"clusters"`
}

type Listener struct {
	Name         string        `json:"name"`
	Address      Address       `json:"address"`
	FilterChains []FilterChain `json:"filter_chains"`
}

type Address struct {
	SocketAddress SocketAddress `json:"socket_address"`
}

type SocketAddress struct {
	Address   string `json:"address"`
	PortValue int    `json:"port_value"`
}

type FilterChain struct {
	FilterChainMatch *FilterChainMatch `json:"filter_chain_match,omitempty"`
	Filters          []Filter          `json:"filters"`
}

type FilterChainMatch struct {
	ServerNames []string `json:"server_names,omitempty"`
}

type Filter struct {
	Name        string                 `json:"name"`
	TypedConfig map[string]interface{} `json:"typed_config"`
}

type VirtualHost struct {
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
	Routes  []Route  `json:"routes"`
}

type Route struct {
	Match  RouteMatch  `json:"match"`
	Route  *RouteAction `json:"route,omitempty"`
	Redirect *RedirectAction `json:"redirect,omitempty"`
}

type RouteMatch struct {
	Prefix string `json:"prefix"`
}

type RouteAction struct {
	Cluster        string       `json:"cluster"`
	Timeout        string       `json:"timeout"`
	RetryPolicy    *RetryPolicy `json:"retry_policy,omitempty"`
	HostRewriteLiteral string  `json:"host_rewrite_literal,omitempty"`
}

type RedirectAction struct {
	HttpsRedirect bool `json:"https_redirect"`
}

type RetryPolicy struct {
	RetryOn    string `json:"retry_on"`
	NumRetries int    `json:"num_retries"`
}

type Cluster struct {
	Name           string           `json:"name"`
	ConnectTimeout string           `json:"connect_timeout"`
	Type           string           `json:"type"`
	LbPolicy       string           `json:"lb_policy"`
	LoadAssignment LoadAssignment   `json:"load_assignment"`
	TransportSocket *TransportSocket `json:"transport_socket,omitempty"`
}

type TransportSocket struct {
	Name        string                 `json:"name"`
	TypedConfig map[string]interface{} `json:"typed_config"`
}

type LoadAssignment struct {
	ClusterName string        `json:"cluster_name"`
	Endpoints   []LocalityEndpoints `json:"endpoints"`
}

type LocalityEndpoints struct {
	LbEndpoints []LbEndpoint `json:"lb_endpoints"`
}

type LbEndpoint struct {
	Endpoint            Endpoint `json:"endpoint"`
	LoadBalancingWeight int      `json:"load_balancing_weight,omitempty"`
}

type Endpoint struct {
	Address Address `json:"address"`
}

// Compiler transforms domain topologies from the control plane into Envoy v3 configuration
type Compiler struct {
	adminPort   int
	httpPort    int
	httpsPort   int
	edgeVersion string
}

func NewCompiler(adminPort, httpPort, httpsPort int) *Compiler {
	if adminPort == 0 {
		adminPort = 9901
	}
	if httpPort == 0 {
		httpPort = 80
	}
	if httpsPort == 0 {
		httpsPort = 443
	}
	return &Compiler{
		adminPort:   adminPort,
		httpPort:    httpPort,
		httpsPort:   httpsPort,
		edgeVersion: "v1.0.0",
	}
}

// Compile compiles active domain topologies into an Envoy v3 configuration
func (c *Compiler) Compile(topologies []*store.DomainTopology) (*EnvoyConfig, error) {
	config := &EnvoyConfig{
		Admin: Admin{
			Address: Address{
				SocketAddress: SocketAddress{
					Address:   "127.0.0.1",
					PortValue: c.adminPort,
				},
			},
		},
		StaticResources: StaticResources{
			Listeners: make([]Listener, 0),
			Clusters:  make([]Cluster, 0),
		},
	}

	clustersMap := make(map[string]Cluster)
	httpsVirtualHosts := make([]VirtualHost, 0)
	httpVirtualHosts := make([]VirtualHost, 0)

	for _, topo := range topologies {
		if topo.Domain == nil || topo.Domain.Status != model.DomainStatusActive {
			continue // Invariant: Only compile active domains (Rule 17)
		}

		hostname := strings.ToLower(topo.Domain.Hostname)
		vh := VirtualHost{
			Name:    fmt.Sprintf("vhost_%s", sanitizeName(hostname)),
			Domains: []string{hostname, fmt.Sprintf("%s:*", hostname)},
			Routes:  make([]Route, 0),
		}

		// Also build an HTTP redirect virtual host
		httpVh := VirtualHost{
			Name:    fmt.Sprintf("http_redirect_%s", sanitizeName(hostname)),
			Domains: []string{hostname, fmt.Sprintf("%s:*", hostname)},
			Routes: []Route{
				{
					Match: RouteMatch{Prefix: "/"},
					Redirect: &RedirectAction{
						HttpsRedirect: true,
					},
				},
			},
		}
		httpVirtualHosts = append(httpVirtualHosts, httpVh)

		// Process routes and their upstream clusters
		for _, r := range topo.Routes {
			pool, exists := topo.Pools[r.PoolID]
			if !exists || pool == nil || len(pool.Origins) == 0 {
				continue
			}

			clusterName := fmt.Sprintf("cluster_%s", pool.ID)

			timeoutStr := "15s"
			if r.TimeoutMs > 0 {
				timeoutStr = fmt.Sprintf("%.2fs", float64(r.TimeoutMs)/1000.0)
			}

			vh.Routes = append(vh.Routes, Route{
				Match: RouteMatch{
					Prefix: r.PathPrefix,
				},
				Route: &RouteAction{
					Cluster: clusterName,
					Timeout: timeoutStr,
					RetryPolicy: &RetryPolicy{
						RetryOn:    "5xx,connect-failure,refused-stream,gateway-error",
						NumRetries: 2,
					},
				},
			})

			// Add cluster to map if not already built
			if _, alreadyExists := clustersMap[clusterName]; !alreadyExists {
				cluster := c.buildCluster(clusterName, pool)
				clustersMap[clusterName] = cluster
			}
		}

		httpsVirtualHosts = append(httpsVirtualHosts, vh)
	}

	// 1. Build Port 80 HTTP Ingress Listener (Redirects to HTTPS)
	httpListener := c.buildHTTPListener(httpVirtualHosts)
	config.StaticResources.Listeners = append(config.StaticResources.Listeners, httpListener)

	// 2. Build Port 443 HTTPS Ingress Listener
	httpsListener := c.buildHTTPSListener(httpsVirtualHosts, topologies)
	config.StaticResources.Listeners = append(config.StaticResources.Listeners, httpsListener)

	// 3. Collect all unique upstream clusters
	for _, cluster := range clustersMap {
		config.StaticResources.Clusters = append(config.StaticResources.Clusters, cluster)
	}

	return config, nil
}

func (c *Compiler) buildHTTPListener(virtualHosts []VirtualHost) Listener {
	routeConfig := map[string]interface{}{
		"name":          "edge_http_routes",
		"virtual_hosts": virtualHosts,
	}

	hcmConfig := map[string]interface{}{
		"@type":        "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
		"stat_prefix":  "edge_http_ingress",
		"route_config": routeConfig,
		"http_filters": []map[string]interface{}{
			{
				"name": "envoy.filters.http.router",
				"typed_config": map[string]interface{}{
					"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router",
				},
			},
		},
	}

	return Listener{
		Name: "edge_http_listener",
		Address: Address{
			SocketAddress: SocketAddress{
				Address:   "0.0.0.0",
				PortValue: c.httpPort,
			},
		},
		FilterChains: []FilterChain{
			{
				Filters: []Filter{
					{
						Name:        "envoy.filters.network.http_connection_manager",
						TypedConfig: hcmConfig,
					},
				},
			},
		},
	}
}

func (c *Compiler) buildHTTPSListener(virtualHosts []VirtualHost, topologies []*store.DomainTopology) Listener {
	routeConfig := map[string]interface{}{
		"name":          "edge_https_routes",
		"virtual_hosts": virtualHosts,
	}

	httpFilters := make([]map[string]interface{}, 0)

	// 1. Check if rate limiting is enabled across any active topologies
	hasRateLimiting := false
	maxRPM := 1000
	for _, topo := range topologies {
		if topo.Security != nil && topo.Security.RateLimitEnabled {
			hasRateLimiting = true
			if topo.Security.RateLimitRPM > 0 && topo.Security.RateLimitRPM < maxRPM {
				maxRPM = topo.Security.RateLimitRPM
			}
		}
	}

	if hasRateLimiting {
		httpFilters = append(httpFilters, map[string]interface{}{
			"name": "envoy.filters.http.local_ratelimit",
			"typed_config": map[string]interface{}{
				"@type":        "type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit",
				"stat_prefix":  "edge_http_local_rate_limiter",
				"status": map[string]interface{}{
					"code": "TooManyRequests",
				},
				"token_bucket": map[string]interface{}{
					"max_tokens":      maxRPM,
					"tokens_per_fill": maxRPM / 60,
					"fill_interval":   "1s",
				},
				"filter_enabled": map[string]interface{}{
					"runtime_key": "local_rate_limit_enabled",
					"default_value": map[string]interface{}{
						"numerator":   100,
						"denominator": "HUNDRED",
					},
				},
				"filter_enforced": map[string]interface{}{
					"runtime_key": "local_rate_limit_enforced",
					"default_value": map[string]interface{}{
						"numerator":   100,
						"denominator": "HUNDRED",
					},
				},
			},
		})
	}

	// 2. Check if any WAF Deny/Block rules exist (IP CIDRs or Path blocks)
	var rbacDenyPrincipals []map[string]interface{}
	for _, topo := range topologies {
		if topo.Security != nil && topo.Security.WAFEnabled {
			for _, rule := range topo.Security.WAFRules {
				if !rule.Enabled || rule.Action != model.WAFActionBlock {
					continue
				}
				if rule.MatchType == model.WAFMatchPathPrefix {
					rbacDenyPrincipals = append(rbacDenyPrincipals, map[string]interface{}{
						"header": map[string]interface{}{
							"name":         ":path",
							"string_match": map[string]interface{}{"prefix": rule.Pattern},
						},
					})
				}
			}
		}
	}

	if len(rbacDenyPrincipals) > 0 {
		httpFilters = append(httpFilters, map[string]interface{}{
			"name": "envoy.filters.http.rbac",
			"typed_config": map[string]interface{}{
				"@type": "type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC",
				"rules": map[string]interface{}{
					"action": "DENY",
					"policies": map[string]interface{}{
						"edge_waf_block_policy": map[string]interface{}{
							"permissions": []map[string]interface{}{{"any": true}},
							"principals":  rbacDenyPrincipals,
						},
					},
				},
			},
		})
	}

	// 3. Check if CDN Caching is enabled across active topologies
	hasCache := false
	for _, topo := range topologies {
		if topo.Cache != nil && topo.Cache.CacheEnabled {
			hasCache = true
			break
		}
	}

	if hasCache {
		httpFilters = append(httpFilters, map[string]interface{}{
			"name": "envoy.filters.http.cache",
			"typed_config": map[string]interface{}{
				"@type": "type.googleapis.com/envoy.extensions.filters.http.cache.v3.CacheConfig",
				"typed_config": map[string]interface{}{
					"@type": "type.googleapis.com/envoy.extensions.cache.simple_http_cache.v3.SimpleHttpCacheConfig",
				},
				"allowed_vary_headers": []map[string]interface{}{
					{"exact": "accept-encoding"},
				},
			},
		})
	}

	// 4. Router filter (final terminal filter)
	httpFilters = append(httpFilters, map[string]interface{}{
		"name": "envoy.filters.http.router",
		"typed_config": map[string]interface{}{
			"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router",
		},
	})

	hcmConfig := map[string]interface{}{
		"@type":        "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
		"stat_prefix":  "edge_https_ingress",
		"route_config": routeConfig,
		"http_filters": httpFilters,
	}

	return Listener{
		Name: "edge_https_listener",
		Address: Address{
			SocketAddress: SocketAddress{
				Address:   "0.0.0.0",
				PortValue: c.httpsPort,
			},
		},
		FilterChains: []FilterChain{
			{
				Filters: []Filter{
					{
						Name:        "envoy.filters.network.http_connection_manager",
						TypedConfig: hcmConfig,
					},
				},
			},
		},
	}
}

func (c *Compiler) buildCluster(clusterName string, pool *model.OriginPool) Cluster {
	// Determine cluster discovery type: STRICT_DNS for domain origins, STATIC for raw IPs
	clusterType := "STRICT_DNS"
	isAllIPs := true
	hasHTTPS := false

	lbEndpoints := make([]LbEndpoint, 0)
	for _, o := range pool.Origins {
		if !o.Healthy {
			continue // Exclude unhealthy endpoints from active rotation (Rule 16)
		}

		if net.ParseIP(o.Address) == nil {
			isAllIPs = false
		}
		if o.Protocol == model.ProtocolHTTPS {
			hasHTTPS = true
		}

		weight := o.Weight
		if weight <= 0 {
			weight = 100
		}

		lbEndpoints = append(lbEndpoints, LbEndpoint{
			Endpoint: Endpoint{
				Address: Address{
					SocketAddress: SocketAddress{
						Address:   o.Address,
						PortValue: o.Port,
					},
				},
			},
			LoadBalancingWeight: weight,
		})
	}

	if isAllIPs && len(lbEndpoints) > 0 {
		clusterType = "STATIC"
	}

	lbPolicy := "ROUND_ROBIN"
	if pool.LBAlgorithm == model.LBAlgorithmLeastLatency {
		lbPolicy = "LEAST_REQUEST"
	}

	cluster := Cluster{
		Name:           clusterName,
		ConnectTimeout: "3s",
		Type:           clusterType,
		LbPolicy:       lbPolicy,
		LoadAssignment: LoadAssignment{
			ClusterName: clusterName,
			Endpoints: []LocalityEndpoints{
				{
					LbEndpoints: lbEndpoints,
				},
			},
		},
	}

	// If origin protocol is HTTPS, attach Upstream TLS context with SNI
	if hasHTTPS && len(pool.Origins) > 0 {
		sniHost := pool.Origins[0].Address
		cluster.TransportSocket = &TransportSocket{
			Name: "envoy.transport_sockets.tls",
			TypedConfig: map[string]interface{}{
				"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
				"sni":   sniHost,
			},
		}
	}

	return cluster
}

func sanitizeName(s string) string {
	r := strings.NewReplacer(".", "_", "-", "_", ":", "_")
	return r.Replace(s)
}

// ToJSON returns indented JSON representation of the compiled Envoy configuration
func (c *EnvoyConfig) ToJSON() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}
