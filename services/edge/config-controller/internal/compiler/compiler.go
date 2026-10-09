package compiler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

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
	Name                   string                   `json:"name"`
	ConnectTimeout         string                   `json:"connect_timeout"`
	Type                   string                   `json:"type"`
	LbPolicy               string                   `json:"lb_policy"`
	LoadAssignment         LoadAssignment           `json:"load_assignment"`
	Http2ProtocolOptions   *map[string]interface{}  `json:"http2_protocol_options,omitempty"`
	HealthChecks           []map[string]interface{} `json:"health_checks,omitempty"`
	TransportSocket        *TransportSocket         `json:"transport_socket,omitempty"`
	TransportSocketMatches []TransportSocketMatch   `json:"transport_socket_matches,omitempty"`
}

type TransportSocketMatch struct {
	Name            string                 `json:"name"`
	Match           map[string]interface{} `json:"match"`
	TransportSocket *TransportSocket       `json:"transport_socket"`
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
	Endpoint            Endpoint               `json:"endpoint"`
	LoadBalancingWeight int                    `json:"load_balancing_weight,omitempty"`
	Metadata            map[string]interface{} `json:"metadata,omitempty"`
}

type Endpoint struct {
	Address Address `json:"address"`
}

// DNSResolver resolves a domain name into IP addresses for validation and static pinning.
type DNSResolver func(ctx context.Context, host string) ([]net.IP, error)

// Compiler transforms domain topologies from the control plane into Envoy v3 configuration
type Compiler struct {
	adminPort    int
	httpPort     int
	httpsPort    int
	acmeHost     string
	acmePort     int
	edgeVersion  string
	caBundlePath string
	resolver     DNSResolver
}

func isProductionEnvironment() bool {
	env := strings.ToLower(strings.TrimSpace(os.Getenv("NEXUSEDGE_ENV")))
	if env == "" {
		env = strings.ToLower(strings.TrimSpace(os.Getenv("ENV")))
	}
	return env == "production"
}

func allowsUnvalidatedDevTLS() bool {
	env := strings.ToLower(strings.TrimSpace(os.Getenv("NEXUSEDGE_ENV")))
	if env == "" {
		env = strings.ToLower(strings.TrimSpace(os.Getenv("ENV")))
	}
	return os.Getenv("NEXUSEDGE_DEV_MODE") == "true" && (env == "development" || env == "test")
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

	caBundlePath := os.Getenv("NEXUSEDGE_UPSTREAM_CA_FILE")
	if caBundlePath == "" {
		caBundlePath = "/etc/ssl/certs/ca-certificates.crt"
	}

	defaultResolver := func(ctx context.Context, host string) ([]net.IP, error) {
		resolveCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		return net.DefaultResolver.LookupIP(resolveCtx, "ip", host)
	}

	return &Compiler{
		adminPort:    adminPort,
		httpPort:     httpPort,
		httpsPort:    httpsPort,
		acmeHost:     acmeHost,
		acmePort:     acmePort,
		edgeVersion:  "v1.0.0",
		caBundlePath: caBundlePath,
		resolver:     defaultResolver,
	}
}

func (c *Compiler) SetDNSResolver(r DNSResolver) {
	c.resolver = r
}

func (c *Compiler) GetDNSResolver() DNSResolver {
	return c.resolver
}

func (c *Compiler) SetCABundlePath(path string) {
	c.caBundlePath = path
}

func (c *Compiler) GetCABundlePath() string {
	return c.caBundlePath
}

func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

func calculateTokenBucket(rpm int, burstSize int) (maxTokens int, tokensPerFill int, fillInterval string) {
	if rpm <= 0 {
		rpm = 6000
	}
	g := gcd(rpm, 60)
	tokensPerFill = rpm / g
	fillSeconds := 60 / g
	fillInterval = fmt.Sprintf("%ds", fillSeconds)

	maxTokens = burstSize
	if maxTokens <= 0 {
		maxTokens = rpm
	}
	if maxTokens < tokensPerFill {
		maxTokens = tokensPerFill
	}
	return maxTokens, tokensPerFill, fillInterval
}

// CalculateTokenBucket exposes token bucket calculations for rate limit rules
func CalculateTokenBucket(rpm int, burstSize int) (maxTokens int, tokensPerFill int, fillInterval string) {
	return calculateTokenBucket(rpm, burstSize)
}

func buildLocalRateLimitConfig(statPrefix string, rpm int, burstSize int) map[string]interface{} {
	maxTokens, tokensPerFill, fillInterval := calculateTokenBucket(rpm, burstSize)
	return map[string]interface{}{
		"@type":       "type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit",
		"stat_prefix": statPrefix,
		"token_bucket": map[string]interface{}{
			"max_tokens":      maxTokens,
			"tokens_per_fill": tokensPerFill,
			"fill_interval":   fillInterval,
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

		// Per-Domain & Per-Route Rate Limit Policy (Finding 6 & Finding 8)
		pathRules := make(map[string]model.RateLimitRule)
		var domainWideRule *model.RateLimitRule

		if topo.Security != nil && topo.Security.RateLimitEnabled {
			for _, rlRule := range topo.Security.RateLimitRules {
				pfx := strings.TrimSpace(rlRule.PathPrefix)
				if pfx != "" && pfx != "/" {
					pathRules[pfx] = rlRule
				} else if domainWideRule == nil {
					copyRule := rlRule
					domainWideRule = &copyRule
				}
			}

			// Domain-wide rate limit configuration on VirtualHost
			if domainWideRule != nil {
				rpm := domainWideRule.RequestsPerMinute
				if rpm <= 0 {
					rpm = topo.Security.RateLimitRPM
				}
				vh.TypedPerFilterConfig = map[string]interface{}{
					"envoy.filters.http.local_ratelimit": buildLocalRateLimitConfig(
						fmt.Sprintf("vh_rate_limit_%s", sanitizeName(hostname)),
						rpm,
						domainWideRule.BurstSize,
					),
				}
			} else if len(pathRules) == 0 && topo.Security.RateLimitRPM > 0 {
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

			// Apply path-specific rate limiting to matching route (Finding 6)
			if topo.Security != nil && topo.Security.RateLimitEnabled && len(pathRules) > 0 {
				var matchedRule *model.RateLimitRule
				if rule, ok := pathRules[r.PathPrefix]; ok {
					matchedRule = &rule
				} else {
					for pfx, rule := range pathRules {
						if strings.HasPrefix(r.PathPrefix, pfx) {
							if matchedRule == nil || len(pfx) > len(matchedRule.PathPrefix) {
								copyR := rule
								matchedRule = &copyR
							}
						}
					}
				}

				if matchedRule != nil {
					rRPM := matchedRule.RequestsPerMinute
					if rRPM <= 0 {
						rRPM = topo.Security.RateLimitRPM
					}
					routeStat := fmt.Sprintf("route_rate_limit_%s_%s", sanitizeName(hostname), sanitizeName(r.PathPrefix))
					routeObj.TypedPerFilterConfig = map[string]interface{}{
						"envoy.filters.http.local_ratelimit": buildLocalRateLimitConfig(routeStat, rRPM, matchedRule.BurstSize),
					}
				}
			}

			customerRoutes = append(customerRoutes, routeObj)
			vh.Routes = append(vh.Routes, routeObj)

			// Add cluster to map if not already built
			if _, alreadyExists := clustersMap[clusterName]; !alreadyExists {
				cluster, err := c.buildCluster(clusterName, pool)
				if err != nil {
					return nil, err
				}
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
		httpListener, err := c.buildHTTPListener(httpVirtualHosts, orderedTopologies, anyServingDirectHTTP)
		if err != nil {
			return nil, err
		}
		config.StaticResources.Listeners = append(config.StaticResources.Listeners, httpListener)

		httpsListener, err := c.buildHTTPSListener(httpsVirtualHosts, orderedTopologies)
		if err != nil {
			return nil, err
		}
		config.StaticResources.Listeners = append(config.StaticResources.Listeners, httpsListener)
		// Register SDS gRPC cluster so DownstreamTlsContext has no dangling cluster reference (P0 Finding 6B)
		clustersMap["sds-grpc-cluster"] = c.buildSDSCluster()
	} else {
		// When only HTTP is available before TLS issuance, serve customer routes directly on port 80
		httpListener, err := c.buildHTTPListener(httpVirtualHosts, orderedTopologies, true)
		if err != nil {
			return nil, err
		}
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

func isPoPAllowed(allowed []string, target string) bool {
	if len(allowed) == 0 {
		return true // empty means global / all PoPs
	}
	for _, p := range allowed {
		if strings.EqualFold(strings.TrimSpace(p), target) {
			return true
		}
	}
	return false
}

// CompileForPoP compiles domain topologies into an Envoy configuration tailored for a specific PoP (P1 Finding).
// It defensively filters topologies by popID, ensuring domains and origins restricted to other PoPs are excluded.
func (c *Compiler) CompileForPoP(popID string, topologies []*store.DomainTopology) (*EnvoyConfig, error) {
	targetPoP := strings.ToLower(strings.TrimSpace(popID))
	filteredTopologies := make([]*store.DomainTopology, 0, len(topologies))

	for _, topo := range topologies {
		if topo == nil || topo.Domain == nil || topo.Domain.Status != model.DomainStatusActive {
			continue
		}

		// Filter domains restricted to other PoPs (P1 Isolation)
		if !isPoPAllowed(topo.Domain.AllowedPoPs, targetPoP) {
			continue
		}

		// Filter origin pools and individual origins
		filteredPools := make(map[string]*model.OriginPool)
		for poolID, pool := range topo.Pools {
			if pool == nil {
				continue
			}
			if !isPoPAllowed(pool.AllowedPoPs, targetPoP) {
				continue
			}

			var validOrigins []model.Origin
			for _, o := range pool.Origins {
				if isPoPAllowed(o.AllowedPoPs, targetPoP) {
					validOrigins = append(validOrigins, o)
				}
			}

			if len(validOrigins) > 0 {
				poolCopy := *pool
				poolCopy.Origins = validOrigins
				filteredPools[poolID] = &poolCopy
			}
		}

		// P2 Finding 8: If domain has configured routes, verify there is at least one usable pool with valid origins for this PoP.
		// If 0 usable origins exist at this PoP, omit domain to prevent empty VirtualHost and routing blackholes.
		if len(topo.Routes) > 0 && len(filteredPools) == 0 {
			continue
		}

		hasUsableRoute := false
		usableRoutes := make([]*model.Route, 0, len(topo.Routes))
		for _, r := range topo.Routes {
			if pool, ok := filteredPools[r.PoolID]; ok && len(pool.Origins) > 0 {
				hasUsableRoute = true
				usableRoutes = append(usableRoutes, r)
			}
		}
		if len(topo.Routes) > 0 && !hasUsableRoute {
			continue
		}

		topoCopy := *topo
		topoCopy.Routes = usableRoutes
		topoCopy.Pools = filteredPools
		filteredTopologies = append(filteredTopologies, &topoCopy)
	}

	config, err := c.Compile(filteredTopologies)
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

func (c *Compiler) buildHTTPFilters(topologies []*store.DomainTopology) ([]map[string]interface{}, error) {
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
		// Listener-level default rate-limit filter.
		// Enabled runtime key default is 0 so rate limiting is strictly applied per virtual host token bucket (Finding 8)
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
						"numerator":   0,
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
				} else if rule.MatchType == model.WAFMatchIPCIDR {
					// IP CIDR matching scoped to tenant authority (Finding 7)
					rawPattern := strings.TrimSpace(rule.Pattern)
					var ipPrefix string
					var prefixLen int
					if strings.Contains(rawPattern, "/") {
						_, ipNet, err := net.ParseCIDR(rawPattern)
						if err != nil {
							return nil, fmt.Errorf("invalid WAF IP CIDR pattern %q for rule %q: %w", rawPattern, rule.ID, err)
						}
						size, _ := ipNet.Mask.Size()
						ipPrefix = ipNet.IP.String()
						prefixLen = size
					} else {
						parsedIP := net.ParseIP(rawPattern)
						if parsedIP == nil {
							return nil, fmt.Errorf("invalid WAF IP address pattern %q for rule %q", rawPattern, rule.ID)
						}
						ipPrefix = parsedIP.String()
						if parsedIP.To4() != nil {
							prefixLen = 32
						} else {
							prefixLen = 128
						}
					}

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
									"direct_remote_ip": map[string]interface{}{
										"address_prefix": ipPrefix,
										"prefix_len":     prefixLen,
									},
								},
							},
						},
					})
				} else {
					return nil, fmt.Errorf("unsupported WAF match type %q for block rule %q", rule.MatchType, rule.ID)
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

	return httpFilters, nil
}

func (c *Compiler) buildHTTPListener(virtualHosts []VirtualHost, topologies []*store.DomainTopology, isServingDirect bool) (Listener, error) {
	routeConfig := map[string]interface{}{
		"name":          "edge_http_routes",
		"virtual_hosts": virtualHosts,
	}

	var httpFilters []map[string]interface{}
	if isServingDirect {
		filters, err := c.buildHTTPFilters(topologies)
		if err != nil {
			return Listener{}, err
		}
		httpFilters = filters
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
	}, nil
}

func (c *Compiler) buildHTTPSListener(virtualHosts []VirtualHost, topologies []*store.DomainTopology) (Listener, error) {
	routeConfig := map[string]interface{}{
		"name":          "edge_https_routes",
		"virtual_hosts": virtualHosts,
	}

	httpFilters, err := c.buildHTTPFilters(topologies)
	if err != nil {
		return Listener{}, err
	}

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
	}, nil
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

func effectiveOriginSNI(o model.Origin) string {
	if sni := strings.TrimSpace(o.SNI); sni != "" {
		return sni
	}
	// IP-literal destination has no DNS SNI name
	// unless a hostname has been explicitly configured.
	if net.ParseIP(strings.TrimSpace(o.Address)) != nil {
		return ""
	}
	return strings.TrimSpace(o.Address)
}

// Runtime DNS Rebinding Protection (Option B: Validated IP-pinned STATIC endpoints):
// Resolves origin hostnames, validates that all resolved destination IPs are public and safe,
// and pins them as STATIC cluster endpoints with preserved SNI, completely shielding Envoy
// from runtime DNS rebinding to loopback, RFC1918, or cloud metadata ranges (P1 Finding).
func (c *Compiler) buildCluster(clusterName string, pool *model.OriginPool) (Cluster, error) {
	// Pinned STATIC endpoints shield Envoy from runtime DNS rebinding SSRF (Rule 23, Finding 1)
	clusterType := "STATIC"
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

		sniHost := effectiveOriginSNI(o)
		var endpointMeta map[string]interface{}
		if o.Protocol == model.ProtocolHTTPS && sniHost != "" {
			endpointMeta = map[string]interface{}{
				"filter_metadata": map[string]interface{}{
					"envoy.transport_socket_match": map[string]interface{}{
						"sni_host": sniHost,
					},
				},
			}
		}

		parsedIP := net.ParseIP(o.Address)
		if parsedIP != nil {
			// Direct IP destination: validate against SSRF private/reserved ranges
			if onboarding.IsPrivateOrReservedIP(parsedIP) {
				if os.Getenv("NEXUSEDGE_DEV_MODE") == "true" && onboarding.IsExplicitDevEnvironment() {
					// Permitted in isolated development/test profile for mock origins
				} else {
					continue // Exclude unsafe private IP destination
				}
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
				Metadata:            endpointMeta,
			})
		} else {
			// Origin is an FQDN: Fail-closed without resolver or if resolution fails/unsafe (P1 Finding 1)
			if c.resolver == nil {
				continue
			}

			resolveCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			resolvedIPs, err := c.resolver(resolveCtx, o.Address)
			cancel()
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
					Metadata:            endpointMeta,
				})
			}
		}
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

	// If origin protocol is HTTPS and homogenous (no mixed plain HTTP), attach Upstream TLS context with SNI and trusted CA validation
	if hasHTTPS && !hasHTTP && len(pool.Origins) > 0 {
		type sniInfo struct {
			sni          string
			caBundlePath string
		}
		uniqueSNIs := make([]sniInfo, 0)
		sniSeen := make(map[string]bool)
		for _, orig := range pool.Origins {
			if orig.Protocol == model.ProtocolHTTPS {
				sni := effectiveOriginSNI(orig)
				caPath := orig.CABundlePath
				key := strings.ToLower(sni) + "|" + caPath
				if !sniSeen[key] {
					sniSeen[key] = true
					uniqueSNIs = append(uniqueSNIs, sniInfo{
						sni:          sni,
						caBundlePath: caPath,
					})
				}
			}
		}

		if len(uniqueSNIs) == 1 {
			target := uniqueSNIs[0].sni
			if target == "" && len(pool.Origins) > 0 {
				target = pool.Origins[0].Address
			}
			tlsCtx, err := c.buildValidatedUpstreamTLSContext(target, uniqueSNIs[0].caBundlePath)
			if err != nil {
				return Cluster{}, err
			}
			cluster.TransportSocket = &TransportSocket{
				Name:        "envoy.transport_sockets.tls",
				TypedConfig: tlsCtx,
			}
		} else if len(uniqueSNIs) > 1 {
			// Per-origin endpoint TLS matching: prevents SNI mismatches when origins have distinct hostnames (Finding 3)
			for _, item := range uniqueSNIs {
				target := item.sni
				if target == "" && len(pool.Origins) > 0 {
					target = pool.Origins[0].Address
				}
				tlsCtx, err := c.buildValidatedUpstreamTLSContext(target, item.caBundlePath)
				if err != nil {
					return Cluster{}, err
				}
				matchName := sanitizeName(item.sni)
				if matchName == "" {
					matchName = "default"
				}
				cluster.TransportSocketMatches = append(cluster.TransportSocketMatches, TransportSocketMatch{
					Name: fmt.Sprintf("tls_match_%s", matchName),
					Match: map[string]interface{}{
						"sni_host": item.sni,
					},
					TransportSocket: &TransportSocket{
						Name:        "envoy.transport_sockets.tls",
						TypedConfig: tlsCtx,
					},
				})
			}
			// Cluster-level fallback TransportSocket
			fallbackTarget := uniqueSNIs[0].sni
			if fallbackTarget == "" && len(pool.Origins) > 0 {
				fallbackTarget = pool.Origins[0].Address
			}
			fallbackCtx, err := c.buildValidatedUpstreamTLSContext(fallbackTarget, uniqueSNIs[0].caBundlePath)
			if err != nil {
				return Cluster{}, err
			}
			cluster.TransportSocket = &TransportSocket{
				Name:        "envoy.transport_sockets.tls",
				TypedConfig: fallbackCtx,
			}
		} else if len(uniqueSNIs) == 0 {
			// Direct IP HTTPS upstream without SNI extension
			defaultCA := ""
			originTarget := ""
			if len(pool.Origins) > 0 {
				defaultCA = pool.Origins[0].CABundlePath
				originTarget = pool.Origins[0].Address
			}
			tlsCtx, err := c.buildValidatedUpstreamTLSContext(originTarget, defaultCA)
			if err != nil {
				return Cluster{}, err
			}
			cluster.TransportSocket = &TransportSocket{
				Name:        "envoy.transport_sockets.tls",
				TypedConfig: tlsCtx,
			}
		}
	}

	return cluster, nil
}

// BuildValidatedUpstreamTLSContext exposes upstream TLS context construction for verification
func (c *Compiler) BuildValidatedUpstreamTLSContext(sni string, caBundlePath string) (map[string]interface{}, error) {
	return c.buildValidatedUpstreamTLSContext(sni, caBundlePath)
}

// buildValidatedUpstreamTLSContext constructs a fully-validated Envoy v3 UpstreamTlsContext.
// Configures SNI, trusted CA bundle validation, and exact Subject Alternative Name (SAN) matching
// for DNS hostnames and IP addresses, preventing upstream TLS impersonation (P1 Finding 1).
func (c *Compiler) buildValidatedUpstreamTLSContext(sni string, caBundlePath string) (map[string]interface{}, error) {
	effectiveCAPath := strings.TrimSpace(caBundlePath)
	if effectiveCAPath == "" {
		effectiveCAPath = strings.TrimSpace(c.caBundlePath)
	}
	if effectiveCAPath == "" {
		effectiveCAPath = strings.TrimSpace(os.Getenv("NEXUSEDGE_UPSTREAM_CA_FILE"))
	}

	if isProductionEnvironment() && effectiveCAPath == "" {
		return nil, errors.New("upstream TLS validation requires trusted CA bundle in production; empty CA bundle path is rejected")
	}
	if effectiveCAPath == "" && !allowsUnvalidatedDevTLS() {
		return nil, errors.New("upstream TLS validation requires trusted CA bundle; unvalidated upstream TLS is forbidden outside explicit development/test mode")
	}

	commonTLS := map[string]interface{}{}
	if effectiveCAPath != "" {
		validationCtx := map[string]interface{}{
			"trusted_ca": map[string]interface{}{
				"filename": effectiveCAPath,
			},
		}

		cleanTarget := strings.TrimSpace(sni)
		if cleanTarget != "" {
			sanType := "DNS"
			if net.ParseIP(cleanTarget) != nil {
				sanType = "IP_ADDRESS"
			}
			validationCtx["match_typed_subject_alt_names"] = []map[string]interface{}{
				{
					"san_type": sanType,
					"matcher": map[string]interface{}{
						"exact": cleanTarget,
					},
				},
			}
		}

		commonTLS["validation_context"] = validationCtx
	}

	tlsContext := map[string]interface{}{
		"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
	}
	cleanTarget := strings.TrimSpace(sni)
	if cleanTarget != "" && net.ParseIP(cleanTarget) == nil {
		tlsContext["sni"] = cleanTarget
	}
	if len(commonTLS) > 0 {
		tlsContext["common_tls_context"] = commonTLS
	}

	return tlsContext, nil
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
	r := strings.NewReplacer(".", "_", "-", "_", ":", "_", "/", "_")
	return strings.Trim(r.Replace(s), "_")
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
