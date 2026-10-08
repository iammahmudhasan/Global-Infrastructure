package onboarding

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/store"
)

var (
	ErrInvalidHostname = errors.New("invalid hostname: must be a valid fully-qualified domain name (FQDN)")
	ErrInvalidOrigin   = errors.New("invalid origin: must specify a valid host and port")
	hostnameRegex      = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
)

type OnboardRequest struct {
	ProjectID      string   `json:"project_id"`
	Hostname       string   `json:"hostname"`               // e.g. "api.customer.com"
	OriginAddress  string   `json:"origin_address"`         // e.g. "origin.customer.internal" or "203.0.113.10"
	OriginPort     int      `json:"origin_port"`            // default 443
	OriginProtocol string   `json:"origin_protocol"`        // "HTTPS" or "HTTP"
	AllowedPoPs    []string `json:"allowed_pops,omitempty"` // empty means global / all PoPs
}

type OnboardResponse struct {
	DomainID          string             `json:"domain_id"`
	Hostname          string             `json:"hostname"`
	Status            model.DomainStatus `json:"status"`
	CNAMETarget       string             `json:"cname_target"`
	VerificationToken string             `json:"verification_token"`
	DefaultRouteID    string             `json:"default_route_id"`
	OriginPoolID      string             `json:"origin_pool_id"`
	DNSRecordToCreate map[string]string  `json:"dns_record_to_create"`
}

type DomainService struct {
	store *store.Store
}

func NewDomainService(s *store.Store) *DomainService {
	return &DomainService{store: s}
}

func generateID(prefix string) string {
	b := make([]byte, 6)
	rand.Read(b)
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(b))
}

// ValidateHostname enforces RFC 1123 hostname rules and rejects localhost/internal IPs (Rule 23)
func ValidateHostname(host string) error {
	host = strings.ToLower(strings.TrimSpace(host))
	if len(host) < 3 || len(host) > 253 {
		return ErrInvalidHostname
	}
	if host == "localhost" || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return errors.New("invalid domain: private or internal domains not permitted for edge onboarding")
	}
	// Check if IP address was passed instead of domain name
	if ip := net.ParseIP(host); ip != nil {
		return errors.New("hostname cannot be a raw IP address")
	}
	if !hostnameRegex.MatchString(host) {
		return ErrInvalidHostname
	}
	return nil
}

// ValidateOriginAddress enforces anti-SSRF policy (P0 Security, Finding 11)
// Blocks loopback, RFC 1918 private IPv4/IPv6, cloud metadata (169.254.169.254),
// carrier-grade NAT (100.64.0.0/10), and internal hostnames (.local, .internal, localhost).
func ValidateOriginAddress(addr string) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return errors.New("origin address cannot be empty")
	}

	// Reject host:port combination when OriginPort is a separate field (Finding 19)
	if ip := net.ParseIP(addr); ip == nil {
		if strings.Contains(addr, ":") {
			return errors.New("origin_address must not include a port; use origin_port")
		}
	}

	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}

	lowerHost := strings.ToLower(host)
	if lowerHost == "localhost" || strings.HasSuffix(lowerHost, ".local") ||
		strings.HasSuffix(lowerHost, ".internal") || strings.HasSuffix(lowerHost, ".onion") {
		return errors.New("forbidden origin: private, internal, or localhost address not permitted (SSRF protection)")
	}

	if ip := net.ParseIP(host); ip != nil {
		if isPrivateOrReservedIP(ip) {
			return errors.New("forbidden origin: loopback, private RFC1918, link-local, or cloud metadata IP not permitted (SSRF protection)")
		}
		return nil
	}

	if !hostnameRegex.MatchString(host) {
		return errors.New("invalid origin hostname: must be a valid FQDN or public IP")
	}

	return nil
}

// IsPrivateOrReservedIP checks whether an IP address belongs to loopback, private (RFC 1918),
// link-local, cloud metadata (169.254.169.254), carrier-grade NAT (100.64.0.0/10),
// broadcast, multicast, or IPv6 ULA/link-local ranges (Anti-SSRF Protection).
func IsPrivateOrReservedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}

	if ipv4 := ip.To4(); ipv4 != nil {
		if ipv4[0] == 0 {
			return true
		}
		if ipv4[0] == 10 {
			return true
		}
		if ipv4[0] == 172 && (ipv4[1] >= 16 && ipv4[1] <= 31) {
			return true
		}
		if ipv4[0] == 192 && ipv4[1] == 168 {
			return true
		}
		if ipv4[0] == 100 && (ipv4[1] >= 64 && ipv4[1] <= 127) {
			return true
		}
		if ipv4[0] == 169 && ipv4[1] == 254 {
			return true
		}
		if ipv4[0] >= 224 {
			return true
		}
		if ipv4[0] == 255 && ipv4[1] == 255 && ipv4[2] == 255 && ipv4[3] == 255 {
			return true
		}
	} else {
		if len(ip) == net.IPv6len && (ip[0]&0xfe) == 0xfc {
			return true
		}
	}

	return false
}

func isPrivateOrReservedIP(ip net.IP) bool {
	return IsPrivateOrReservedIP(ip)
}

func (s *DomainService) OnboardDomain(req OnboardRequest) (*OnboardResponse, error) {
	if err := ValidateHostname(req.Hostname); err != nil {
		return nil, err
	}
	if err := ValidateOriginAddress(req.OriginAddress); err != nil {
		return nil, err
	}

	// Validate origin port (Finding 18)
	if req.OriginPort == 0 {
		req.OriginPort = 443
	}
	if req.OriginPort < 1 || req.OriginPort > 65535 {
		return nil, errors.New("origin_port must be between 1 and 65535")
	}

	// Validate origin protocol (Finding 18)
	protocol := strings.ToUpper(strings.TrimSpace(req.OriginProtocol))
	if protocol == "" {
		protocol = "HTTPS"
	}
	switch protocol {
	case "HTTP", "HTTPS":
	default:
		return nil, errors.New("origin_protocol must be HTTP or HTTPS")
	}
	req.OriginProtocol = protocol

	hostname := strings.ToLower(strings.TrimSpace(req.Hostname))
	domainID := generateID("dom")
	cnameTarget := fmt.Sprintf("%s.edge.nexusedge.net", domainID)
	verificationToken := generateID("token")

	// 1. Create Domain Entity
	domain := &model.Domain{
		ID:                domainID,
		ProjectID:         req.ProjectID,
		Hostname:          hostname,
		Status:            model.DomainStatusPendingVerification,
		OnboardingType:    "CNAME",
		CNAMETarget:       cnameTarget,
		VerificationToken: verificationToken,
		AllowedPoPs:       req.AllowedPoPs,
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}

	if err := s.store.SaveDomain(domain); err != nil {
		return nil, err
	}

	// 2. Create Default Origin Pool & Endpoint
	poolID := generateID("pool")
	pool := &model.OriginPool{
		ID:          poolID,
		ProjectID:   req.ProjectID,
		Name:        fmt.Sprintf("primary-pool-%s", hostname),
		LBAlgorithm: model.LBAlgorithmRoundRobin,
		AllowedPoPs: req.AllowedPoPs,
	}
	s.store.SaveOriginPool(pool)

	originID := generateID("orig")
	origin := &model.Origin{
		ID:          originID,
		PoolID:      poolID,
		Address:     req.OriginAddress,
		Port:        req.OriginPort,
		Protocol:    model.Protocol(req.OriginProtocol),
		Weight:      100,
		Healthy:     true,
		AllowedPoPs: req.AllowedPoPs,
	}
	if err := s.store.AddOrigin(origin); err != nil {
		_ = s.store.DeleteDomain(domainID)
		return nil, err
	}

	// 3. Create Default Catch-All Route ("/")
	routeID := generateID("rt")
	route := &model.Route{
		ID:         routeID,
		DomainID:   domainID,
		PoolID:     poolID,
		PathPrefix: "/",
		Priority:   0,
		TimeoutMs:  10000,
	}
	s.store.SaveRoute(route)

	// 4. Create Default Security Policy (OWASP WAF + Rate Limit 1000 RPM)
	s.store.SaveSecurityPolicy(&model.SecurityPolicy{
		ID:               generateID("sec"),
		DomainID:         domainID,
		WAFEnabled:       true,
		WAFMode:          "BLOCK",
		RateLimitEnabled: true,
		RateLimitRPM:     1000,
	})

	// 5. Create Default Cache Policy
	s.store.SaveCachePolicy(&model.CachePolicy{
		ID:                   generateID("cache"),
		DomainID:             domainID,
		CacheEnabled:         true,
		DefaultTTLSeconds:    3600,
		RespectOriginHeaders: true,
	})

	return &OnboardResponse{
		DomainID:          domainID,
		Hostname:          hostname,
		Status:            domain.Status,
		CNAMETarget:       cnameTarget,
		VerificationToken: verificationToken,
		DefaultRouteID:    routeID,
		OriginPoolID:      poolID,
		DNSRecordToCreate: map[string]string{
			"type":   "CNAME",
			"name":   hostname,
			"target": cnameTarget,
			"ttl":    "300",
		},
	}, nil
}

func isExplicitDevEnvironment() bool {
	env := strings.ToLower(strings.TrimSpace(os.Getenv("NEXUSEDGE_ENV")))
	if env == "" {
		env = strings.ToLower(strings.TrimSpace(os.Getenv("ENV")))
	}
	return env == "development" || env == "test"
}

// VerifyDomain verifies customer DNS CNAME pointing or TXT challenge and activates the edge route (Finding 10)
func (s *DomainService) VerifyDomain(domainID string) (*model.Domain, error) {
	domain, err := s.store.GetDomain(domainID)
	if err != nil {
		return nil, err
	}

	// In automated local development mode only, permit bypass of external recursive DNS (positive allowlist)
	if os.Getenv("NEXUSEDGE_DEV_MODE") == "true" && isExplicitDevEnvironment() {
		if err := s.store.UpdateDomainStatus(domainID, model.DomainStatusActive); err != nil {
			return nil, err
		}
		domain.Status = model.DomainStatusActive
		return domain, nil
	}

	// Recursive DNS check for CNAME target
	cname, err := net.LookupCNAME(domain.Hostname)
	if err == nil && strings.TrimSuffix(strings.ToLower(cname), ".") == strings.ToLower(domain.CNAMETarget) {
		if err := s.store.UpdateDomainStatus(domainID, model.DomainStatusActive); err != nil {
			return nil, err
		}
		domain.Status = model.DomainStatusActive
		return domain, nil
	}

	// Fallback to TXT verification challenge check: _nexusedge-challenge.<domain> -> token
	txtRecords, txtErr := net.LookupTXT("_nexusedge-challenge." + domain.Hostname)
	if txtErr == nil {
		for _, txt := range txtRecords {
			if strings.TrimSpace(txt) == domain.VerificationToken {
				if err := s.store.UpdateDomainStatus(domainID, model.DomainStatusActive); err != nil {
					return nil, err
				}
				domain.Status = model.DomainStatusActive
				return domain, nil
			}
		}
	}

	// Fail closed by default: DNS proof must be verified
	return nil, fmt.Errorf("domain verification failed: CNAME %s does not point to %s", domain.Hostname, domain.CNAMETarget)
}

// SweepExpiredPendingDomains sweeps unverified pending domains older than maxAge across the store (Finding 2)
func (s *DomainService) SweepExpiredPendingDomains(maxAge time.Duration) int {
	return s.store.SweepExpiredPendingDomains(maxAge)
}
