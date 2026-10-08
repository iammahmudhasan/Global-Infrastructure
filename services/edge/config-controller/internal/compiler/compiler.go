package compiler

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/onboarding"
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
	FilterChainMatch *FilterChainMatch      `json:"filter_chain_match,omitempty"`
	Filters          []Filter               `json:"filters"`
	TransportSocket  map[string]interface{} `json:"transport_socket,omitempty"`
}

type FilterChainMatch struct {
	ServerNames []string `json:"server_names,omitempty"`
}

type Filter struct {
	Name        string                 `json:"name"`
	TypedConfig map[string]interface{} `json:"typed_config"`
}

type VirtualHost struct {
	Name                 string                 `json:"name"`
	Domains              []string               `json:"domains"`
	Routes               []Route                `json:"routes"`
	ResponseHeadersToAdd []HeaderValueOption    `json:"response_headers_to_add,omitempty"`
	TypedPerFilterConfig map[string]interface{} `json:"typed_per_filter_config,omitempty"`
}

type HeaderValueOption struct {
	Header HeaderValue `json:"header"`
	Append bool        `json:"append"`
}

type HeaderValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type Route struct {
	Match                RouteMatch             `json:"match"`
	Route                *RouteAction           `json:"route,omitempty"`
	Redirect             *RedirectAction        `json:"redirect,omitempty"`
	TypedPerFilterConfig map[string]interface{} `json:"typed_per_filter_config,omitempty"`
}

type RouteMatch struct {
	Prefix string `json:"prefix"`
}

type RouteAction struct {
	Cluster            string       `json:"cluster"`
	Timeout            string       `json:"timeout"`
	RetryPolicy        *RetryPolicy `json:"retry_policy,omitempty"`
	HostRewriteLiteral string       `json:"host_rewrite_literal,omitempty"`
}

type RedirectAction struct {
	HttpsRedirect bool `json:"https_redirect"`
}

type RetryPolicy struct {
	RetryOn    string `json:"retry_on"`
	NumRetries int    `json:"num_retries"`
}

type Cluster struct {
	Name                 string                   `json:"name"`
	ConnectTimeout       string                   `json:"connect_timeout"`
	Type                 string                   `json:"type"`
	LbPolicy             string                   `json:"lb_policy"`
	LoadAssignment       LoadAssignment           `json:"load_assignment"`
	Http2ProtocolOptions *map[string]interface{}  `json:"http2_protocol_options,omitempty"`
	HealthChecks         []map[string]interface{} `json:"health_checks,omitempty"`
	TransportSocket      *TransportSocket         `json:"transport_socket,omitempty"`
}

type TransportSocket struct {
	Name        string                 `json:"name"`
	TypedConfig map[string]interface{} `json:"typed_config"`
}

type LoadAssignment struct {
	ClusterName string              `json:"cluster_name"`
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

// DNSResolver resolves a domain name into IP addresses for validation and static pinning.
type DNSResolver func(ctx context.Context, host string) ([]net.IP, error)

// Compiler transforms domain topologies from the control plane into Envoy v3 configuration
type Compiler struct {
	adminPort   int
	httpPort    int
	httpsPort   int
	acmeHost    string
	acmePort    int
	edgeVersion string
	resolver    DNSResolver
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

	acmeHost := os.Getenv("NEXUSEDGE_ACME_HOST")
	if acmeHost == "" {
		acmeHost = "127.0.0.1"
	}
	acmePort := 9091
	if portStr := os.Getenv("NEXUSEDGE_ACME_PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
			acmePort = p
		}
	}

	return &Compiler{
		adminPort:   adminPort,
		httpPort:    httpPort,
		httpsPort:   httpsPort,
		acmeHost:    acmeHost,
		acmePort:    acmePort,
		edgeVersion: "v1.0.0",
	}
}

func (c *Compiler) SetDNSResolver(r DNSResolver) {
	c.resolver = r
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

	// Sort topologies deterministically to prevent output jitter and false rollout churn (P1 Determinism)
	orderedTopologies := append([]*store.DomainTopology(nil), topologies...)
	sort.Slice(orderedTopologies, func(i, j int) bool {
		if orderedTopologies[i].Domain == nil {
			return false
		}
		if orderedTopologies[j].Domain == nil {
			return true
		}

		left := strings.ToLower(orderedTopologies[i].Domain.Hostname)
		right := strings.ToLower(orderedTopologies[j].Domain.Hostname)

		if left != right {
			return left < right
		}

		return orderedTopologies[i].Domain.ID < orderedTopologies[j].Domain.ID
	})

	for _, topo := range orderedTopologies {
		if topo.Domain == nil || topo.Domain.Status != model.DomainStatusActive {
			continue // Invariant: Only compile active domains (Rule 17)
		}

		hostname := strings.ToLower(topo.Domain.Hostname)
		vh := VirtualHost{
			Name:    fmt.Sprintf("vhost_%s", sanitizeName(hostname)),
			Domains: []string{hostname, fmt.Sprintf("%s:*", hostname)},
			Routes: []Route{
				{
					Match: RouteMatch{Prefix: "/.well-known/acme-challenge/"},
					Route: &RouteAction{
						Cluster: "acme_challenge_service",
						Timeout: "5s",
					},
				},
			},
		}

		// HSTS Policy Integration (P1 TLS settings)
		if topo.TLSSettings != nil && topo.TLSSettings.HSTS {
			maxAge := topo.TLSSettings.HSTSMaxAge
			if maxAge <= 0 {
				maxAge = 31536000 // 1 year default
			}
			vh.ResponseHeadersToAdd = append(vh.ResponseHeadersToAdd, HeaderValueOption{
				Header: HeaderValue{
					Key:   "Strict-Transport-Security",
					Value: fmt.Sprintf("max-age=%d; includeSubDomains", maxAge),
				},
				Append: false,
			})
		}

		// Per-Domain VirtualHost Rate Limit Isolation (Finding 9, 14, P1 RPM Audit)
		if topo.Security != nil && topo.Security.RateLimitEnabled && topo.Security.RateLimitRPM > 0 {
			rpm := topo.Security.RateLimitRPM
			vh.TypedPerFilterConfig = map[string]interface{}{
				"envoy.filters.http.local_ratelimit": map[string]interface{}{
					"@type":       "type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit",
					"stat_prefix": fmt.Sprintf("vh_rate_limit_%s", sanitizeName(hostname)),
					"token_bucket": map[string]interface{}{
						"max_tokens":      rpm,
						"tokens_per_fill": rpm,
						"fill_interval":   "60s",
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
			}
		}

		// Per-Domain TLS and EnforceHTTPS Policy Evaluation (P1 Audit)
		hasActiveCert := topo.Certificate != nil &&
			topo.Certificate.Status == model.CertStatusActive &&
			topo.Certificate.CertPEM != ""

		enforceHTTPS := hasActiveCert
		if topo.TLSSettings != nil {
			enforceHTTPS = topo.TLSSettings.EnforceHTTPS && hasActiveCert
		}

		// Build HTTP virtual host:
		// Always bypass ACME HTTP-01 challenge before evaluating customer routing or redirects.
		httpVhName := fmt.Sprintf("http_redirect_%s", sanitizeName(hostname))
		if !enforceHTTPS {
			httpVhName = fmt.Sprintf("http_direct_%s", sanitizeName(hostname))
		}

		httpVh := VirtualHost{
			Name:                 httpVhName,
			Domains:              []string{hostname, fmt.Sprintf("%s:*", hostname)},
			TypedPerFilterConfig: vh.TypedPerFilterConfig,
			Routes: []Route{
				{
					Match: RouteMatch{Prefix: "/.well-known/acme-challenge/"},
					Route: &RouteAction{
						Cluster: "acme_challenge_service",
						Timeout: "5s",
					},
				},
			},
		}

		// Process customer routes and their upstream clusters.
		// Sort routes by Priority descending (highest priority evaluated first in Envoy's first-match route table),
		// tie-breaking by PathPrefix length descending (most specific prefix first),
		// and ID ascending for strict determinism.
		routes := append([]*model.Route(nil), topo.Routes...)
		sort.SliceStable(routes, func(i, j int) bool {
			if routes[i].Priority != routes[j].Priority {
				return routes[i].Priority > routes[j].Priority
			}
			if len(routes[i].PathPrefix) != len(routes[j].PathPrefix) {
				return len(routes[i].PathPrefix) > len(routes[j].PathPrefix)
			}
			if routes[i].PathPrefix != routes[j].PathPrefix {
				return routes[i].PathPrefix > routes[j].PathPrefix
			}
			return routes[i].ID < routes[j].ID
		})

		customerRoutes := make([]Route, 0)
		for _, r := range routes {
			pool, exists := topo.Pools[r.PoolID]
			if !exists || pool == nil || len(pool.Origins) == 0 {
				continue
			}

			clusterName := fmt.Sprintf("cluster_%s", pool.ID)

			timeoutStr := "15s"
			if r.TimeoutMs > 0 {
				timeoutStr = fmt.Sprintf("%.2fs", float64(r.TimeoutMs)/1000.0)
			}

			routeObj := Route{
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
			}
			customerRoutes = append(customerRoutes, routeObj)
			vh.Routes = append(vh.Routes, routeObj)

			// Add cluster to map if not already built
			if _, alreadyExists := clustersMap[clusterName]; !alreadyExists {
				cluster := c.buildCluster(clusterName, pool)
				clustersMap[clusterName] = cluster
			}
		}

		if enforceHTTPS {
			httpVh.Routes = append(httpVh.Routes, Route{
				Match: RouteMatch{Prefix: "/"},
				Redirect: &RedirectAction{
					HttpsRedirect: true,
				},
			})
		} else {
			httpVh.Routes = append(httpVh.Routes, customerRoutes...)
		}

		httpVirtualHosts = append(httpVirtualHosts, httpVh)
		httpsVirtualHosts = append(httpsVirtualHosts, vh)
	}

	// Determine if any active domain has a valid TLS certificate and if any domain serves direct HTTP
	hasCertificates := false
	anyServingDirectHTTP := false
	for _, topo := range orderedTopologies {
		if topo.Domain == nil || topo.Domain.Status != model.DomainStatusActive {
			continue
		}
		hasActiveCert := topo.Certificate != nil &&
			topo.Certificate.Status == model.CertStatusActive &&
			topo.Certificate.CertPEM != ""
		if hasActiveCert {
			hasCertificates = true
		}
		enforceHTTPS := hasActiveCert
		if topo.TLSSettings != nil {
			enforceHTTPS = topo.TLSSettings.EnforceHTTPS && hasActiveCert
		}
		if !enforceHTTPS {
			anyServingDirectHTTP = true
		}
	}

	// 1. Build Ingress Listeners:
	// If active TLS certificates exist, port 443 HTTPS listener is constructed.
	// Port 80 HTTP listener serves redirects or direct routes depending on EnforceHTTPS policies.
	if hasCertificates {
		httpListener := c.buildHTTPListener(httpVirtualHosts, orderedTopologies, anyServingDirectHTTP)
		config.StaticResources.Listeners = append(config.StaticResources.Listeners, httpListener)

		httpsListener := c.buildHTTPSListener(httpsVirtualHosts, orderedTopologies)
		config.StaticResources.Listeners = append(config.StaticResources.Listeners, httpsListener)
		// Register SDS gRPC cluster so DownstreamTlsContext has no dangling cluster reference (P0 Finding 6B)
		clustersMap["sds-grpc-cluster"] = c.buildSDSCluster()
	} else {
		// When only HTTP is available before TLS issuance, serve customer routes directly on port 80
		httpListener := c.buildHTTPListener(httpVirtualHosts, orderedTopologies, true)
		config.StaticResources.Listeners = append(config.StaticResources.Listeners, httpListener)
	}

	// Register ACME challenge cluster whenever active virtual hosts exist (P0 Finding 6A)
	if len(httpVirtualHosts) > 0 || len(httpsVirtualHosts) > 0 {
		clustersMap["acme_challenge_service"] = c.buildACMECluster()
	}

	// 2. Collect all unique upstream clusters with deterministic alphabetical ordering (P1 Determinism)
	clusterNames := make([]string, 0, len(clustersMap))
	for name := range clustersMap {
		clusterNames = append(clusterNames, name)
	}
	sort.Strings(clusterNames)

	for _, name := range clusterNames {
		config.StaticResources.Clusters = append(config.StaticResources.Clusters, clustersMap[name])
	}

	return config, nil
}

// CompileForPoP compiles domain topologies into an Envoy configuration tailored for a specific PoP
func (c *Compiler) CompileForPoP(popID string, topologies []*store.DomainTopology) (*EnvoyConfig, error) {
	config, err := c.Compile(topologies)
	if err != nil {
		return nil, err
	}

	popHeader := HeaderValueOption{
		Header: HeaderValue{
			Key:   "x-nexusedge-pop",
			Value: strings.ToLower(popID),
		},
		Append: false,
	}

	for i := range config.StaticResources.Listeners {
		l := &config.StaticResources.Listeners[i]
		for j := range l.FilterChains {
			fc := &l.FilterChains[j]
			for k := range fc.Filters {
				f := &fc.Filters[k]
				if f.Name == "envoy.filters.network.http_connection_manager" && f.TypedConfig != nil {
					if rc, ok := f.TypedConfig["route_config"].(map[string]interface{}); ok {
						if vhs, ok := rc["virtual_hosts"].([]VirtualHost); ok {
							for vhIdx := range vhs {
								vhs[vhIdx].ResponseHeadersToAdd = append(vhs[vhIdx].ResponseHeadersToAdd, popHeader)
							}
							rc["virtual_hosts"] = vhs
						}
					}
				}
			}
		}
	}

	return config, nil
}

func (c *Compiler) buildHTTPFilters(topologies []*store.DomainTopology) []map[string]interface{} {
	httpFilters := make([]map[string]interface{}, 0)

	// 1. Check if rate limiting is enabled across any active topologies
	hasRateLimiting := false
	for _, topo := range topologies {
		if topo.Security != nil && topo.Security.RateLimitEnabled {
			hasRateLimiting = true
			break
		}
	}

	if hasRateLimiting {
		httpFilters = append(httpFilters, map[string]interface{}{
			"name": "envoy.filters.http.local_ratelimit",
			"typed_config": map[string]interface{}{
				"@type":       "type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit",
				"stat_prefix": "edge_http_local_rate_limiter",
				"status": map[string]interface{}{
					"code": "TooManyRequests",
				},
				"token_bucket": map[string]interface{}{
					"max_tokens":      100000,
					"tokens_per_fill": 10000,
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
					// Tenant Isolation (Finding 14): Scope RBAC rule to match :authority (domain hostname) AND :path
					rbacDenyPrincipals = append(rbacDenyPrincipals, map[string]interface{}{
						"and_ids": map[string]interface{}{
							"ids": []map[string]interface{}{
								{
									"header": map[string]interface{}{
										"name":         ":authority",
										"string_match": map[string]interface{}{"exact": topo.Domain.Hostname},
									},
								},
								{
									"header": map[string]interface{}{
										"name":         ":path",
										"string_match": map[string]interface{}{"prefix": rule.Pattern},
									},
								},
							},
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

	return httpFilters
}

func (c *Compiler) buildHTTPListener(virtualHosts []VirtualHost, topologies []*store.DomainTopology, isServingDirect bool) Listener {
	routeConfig := map[string]interface{}{
		"name":          "edge_http_routes",
		"virtual_hosts": virtualHosts,
	}

	var httpFilters []map[string]interface{}
	if isServingDirect {
		httpFilters = c.buildHTTPFilters(topologies)
	} else {
		httpFilters = []map[string]interface{}{
			{
				"name": "envoy.filters.http.router",
				"typed_config": map[string]interface{}{
					"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router",
				},
			},
		}
	}

	hcmConfig := map[string]interface{}{
		"@type":        "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
		"stat_prefix":  "edge_http_ingress",
		"route_config": routeConfig,
		"access_log":   c.buildAccessLogConfig(),
		"http_filters": httpFilters,
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

	httpFilters := c.buildHTTPFilters(topologies)

	hcmConfig := map[string]interface{}{
		"@type":        "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
		"stat_prefix":  "edge_https_ingress",
		"route_config": routeConfig,
		"access_log":   c.buildAccessLogConfig(),
		"http_filters": httpFilters,
	}

	filterChains := make([]FilterChain, 0)

	for _, topo := range topologies {
		if topo.Certificate != nil && topo.Certificate.Status == model.CertStatusActive && topo.Certificate.CertPEM != "" {
			hostname := strings.ToLower(topo.Domain.Hostname)
			tlsContext := c.buildDownstreamTLSContext(topo.Certificate, topo.TLSSettings)
			filterChains = append(filterChains, FilterChain{
				FilterChainMatch: &FilterChainMatch{
					ServerNames: []string{hostname, fmt.Sprintf("%s:*", hostname)},
				},
				Filters: []Filter{
					{
						Name:        "envoy.filters.network.http_connection_manager",
						TypedConfig: hcmConfig,
					},
				},
				TransportSocket: tlsContext,
			})
		}
	}

	return Listener{
		Name: "edge_https_listener",
		Address: Address{
			SocketAddress: SocketAddress{
				Address:   "0.0.0.0",
				PortValue: c.httpsPort,
			},
		},
		FilterChains: filterChains,
	}
}

func (c *Compiler) buildDownstreamTLSContext(cert *model.Certificate, settings *model.TLSSettings) map[string]interface{} {
	if cert == nil || cert.CertPEM == "" {
		return nil
	}
	minTLS := "TLSv1_2"
	if settings != nil {
		switch settings.MinTLSVersion {
		case "TLSv1.3":
			minTLS = "TLSv1_3"
		case "TLSv1.2", "":
			minTLS = "TLSv1_2"
		}
	}
	// Production Envoy v3 SDS Secret Architecture (Rule 18 Zero Secrets in Config/Logs).
	// Downstream TLS delegates private key discovery to SDS and never inlines plaintext private keys.
	return map[string]interface{}{
		"name": "envoy.transport_sockets.tls",
		"typed_config": map[string]interface{}{
			"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
			"common_tls_context": map[string]interface{}{
				"tls_certificate_sds_secret_configs": []map[string]interface{}{
					{
						"name": fmt.Sprintf("sds-cert-%s", cert.DomainID),
						"sds_config": map[string]interface{}{
							"resource_api_version": "V3",
							"api_config_source": map[string]interface{}{
								"api_type":              "GRPC",
								"transport_api_version": "V3",
								"grpc_services": []map[string]interface{}{
									{
										"envoy_grpc": map[string]interface{}{
											"cluster_name": "sds-grpc-cluster",
										},
									},
								},
							},
						},
					},
				},
				"tls_params": map[string]interface{}{
					"tls_minimum_protocol_version": minTLS,
					"tls_maximum_protocol_version": "TLSv1_3",
				},
			},
		},
	}
}

// Runtime DNS Rebinding Protection (Option B: Validated IP-pinned STATIC endpoints):
// Resolves origin hostnames, validates that all resolved destination IPs are public and safe,
// and pins them as STATIC cluster endpoints with preserved SNI, completely shielding Envoy
// from runtime DNS rebinding to loopback, RFC1918, or cloud metadata ranges (P1 Finding).
func (c *Compiler) buildCluster(clusterName string, pool *model.OriginPool) Cluster {
	// Determine cluster discovery type: STRICT_DNS for domain origins, STATIC for raw IPs
	clusterType := "STRICT_DNS"
	isAllIPs := true
	hasHTTPS := false
	hasHTTP := false

	lbEndpoints := make([]LbEndpoint, 0)
	for _, o := range pool.Origins {
		if !o.Healthy {
			continue // Exclude unhealthy endpoints from active rotation (Rule 16)
		}

		weight := o.Weight
		if weight <= 0 {
			weight = 100
		}

		if o.Protocol == model.ProtocolHTTPS {
			hasHTTPS = true
		} else {
			hasHTTP = true
		}

		parsedIP := net.ParseIP(o.Address)
		if parsedIP != nil {
			// Direct IP destination: validate against SSRF private/reserved ranges
			if onboarding.IsPrivateOrReservedIP(parsedIP) {
				continue // Exclude unsafe private IP destination
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
		} else {
			// Origin is an FQDN:
			if c.resolver != nil {
				resolvedIPs, err := c.resolver(context.Background(), o.Address)
				if err != nil {
					// Unresolvable origin: fail-closed to prevent routing to unverified destinations
					continue
				}

				// Validate every resolved IP against private / loopback / metadata ranges (anti-rebinding)
				hasUnsafeIP := false
				var safeIPs []net.IP
				for _, ip := range resolvedIPs {
					if onboarding.IsPrivateOrReservedIP(ip) {
						hasUnsafeIP = true
						break
					}
					safeIPs = append(safeIPs, ip)
				}

				if hasUnsafeIP || len(safeIPs) == 0 {
					// SSRF / DNS Rebinding detected! Reject completely - never install private destinations in config!
					continue
				}

				// Pin validated public IPs as STATIC endpoints
				for _, ip := range safeIPs {
					lbEndpoints = append(lbEndpoints, LbEndpoint{
						Endpoint: Endpoint{
							Address: Address{
								SocketAddress: SocketAddress{
									Address:   ip.String(),
									PortValue: o.Port,
								},
							},
						},
						LoadBalancingWeight: weight,
					})
				}
			} else {
				// No resolver injected (backward-compatible fallback): retain STRICT_DNS
				isAllIPs = false
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
		}
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

	// Attach active upstream Health Checks if monitor is configured
	if pool.HealthMonitor != nil {
		hm := pool.HealthMonitor
		interval := "10s"
		if hm.IntervalSeconds > 0 {
			interval = fmt.Sprintf("%ds", hm.IntervalSeconds)
		}
		timeout := "2s"
		if hm.TimeoutSeconds > 0 {
			timeout = fmt.Sprintf("%ds", hm.TimeoutSeconds)
		}
		unhealthyThresh := 3
		if hm.UnhealthyThreshold > 0 {
			unhealthyThresh = hm.UnhealthyThreshold
		}
		healthyThresh := 2
		if hm.HealthyThreshold > 0 {
			healthyThresh = hm.HealthyThreshold
		}
		hcPath := hm.Path
		if hcPath == "" {
			hcPath = "/healthz"
		}

		cluster.HealthChecks = []map[string]interface{}{
			{
				"timeout":             timeout,
				"interval":            interval,
				"unhealthy_threshold": unhealthyThresh,
				"healthy_threshold":   healthyThresh,
				"http_health_check": map[string]interface{}{
					"path": hcPath,
				},
			},
		}
	}

	// If origin protocol is HTTPS and homogenous (no mixed plain HTTP), attach Upstream TLS context with SNI
	if hasHTTPS && !hasHTTP && len(pool.Origins) > 0 {
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

func (c *Compiler) buildACMECluster() Cluster {
	clusterType := "STATIC"
	if net.ParseIP(c.acmeHost) == nil {
		clusterType = "STRICT_DNS"
	}
	return Cluster{
		Name:           "acme_challenge_service",
		ConnectTimeout: "2s",
		Type:           clusterType,
		LbPolicy:       "ROUND_ROBIN",
		LoadAssignment: LoadAssignment{
			ClusterName: "acme_challenge_service",
			Endpoints: []LocalityEndpoints{
				{
					LbEndpoints: []LbEndpoint{
						{
							Endpoint: Endpoint{
								Address: Address{
									SocketAddress: SocketAddress{
										Address:   c.acmeHost,
										PortValue: c.acmePort,
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// buildSDSCluster produces the gRPC cluster definition for DownstreamTlsContext SDS secret discovery.
// Architectural Note: In V0 prototype, this endpoint (127.0.0.1:18000) provides declarative Envoy xDS validation.
// A live production SDS secret distribution server is scheduled for V1.
func (c *Compiler) buildSDSCluster() Cluster {
	http2Options := map[string]interface{}{}
	return Cluster{
		Name:                 "sds-grpc-cluster",
		ConnectTimeout:       "2s",
		Type:                 "STATIC",
		LbPolicy:             "ROUND_ROBIN",
		Http2ProtocolOptions: &http2Options,
		LoadAssignment: LoadAssignment{
			ClusterName: "sds-grpc-cluster",
			Endpoints: []LocalityEndpoints{
				{
					LbEndpoints: []LbEndpoint{
						{
							Endpoint: Endpoint{
								Address: Address{
									SocketAddress: SocketAddress{
										Address:   "127.0.0.1",
										PortValue: 18000,
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func sanitizeName(s string) string {
	r := strings.NewReplacer(".", "_", "-", "_", ":", "_")
	return r.Replace(s)
}

func (c *Compiler) buildAccessLogConfig() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"name": "envoy.access_loggers.file",
			"typed_config": map[string]interface{}{
				"@type": "type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog",
				"path":  "/var/log/envoy/access.log",
				"log_format": map[string]interface{}{
					"json_format": map[string]interface{}{
						"start_time":               "%START_TIME%",
						"method":                   "%REQ(:METHOD)%",
						"path":                     "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%",
						"protocol":                 "%PROTOCOL%",
						"response_code":            "%RESPONSE_CODE%",
						"response_flags":           "%RESPONSE_FLAGS%",
						"bytes_received":           "%BYTES_RECEIVED%",
						"bytes_sent":               "%BYTES_SENT%",
						"duration_ms":              "%DURATION%",
						"upstream_service_time_ms": "%RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)%",
						"client_ip":                "%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%",
						"user_agent":               "%REQ(USER-AGENT)%",
						"request_id":               "%REQ(X-REQUEST-ID)%",
						"authority":                "%REQ(:AUTHORITY)%",
						"upstream_cluster":         "%UPSTREAM_CLUSTER%",
					},
				},
			},
		},
	}
}

// ToJSON returns indented JSON representation of the compiled Envoy configuration
func (c *EnvoyConfig) ToJSON() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}
