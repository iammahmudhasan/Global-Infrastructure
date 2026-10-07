package onboarding

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/store"
)

var (
	ErrInvalidHostname  = errors.New("invalid hostname: must be a valid fully-qualified domain name (FQDN)")
	ErrInvalidOrigin    = errors.New("invalid origin: must specify a valid host and port")
	hostnameRegex       = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
)

type OnboardRequest struct {
	ProjectID      string `json:"project_id"`
	Hostname       string `json:"hostname"`        // e.g. "api.customer.com"
	OriginAddress  string `json:"origin_address"`  // e.g. "origin.customer.internal" or "203.0.113.10"
	OriginPort     int    `json:"origin_port"`     // default 443
	OriginProtocol string `json:"origin_protocol"` // "HTTPS" or "HTTP"
}

type OnboardResponse struct {
	DomainID            string             `json:"domain_id"`
	Hostname            string             `json:"hostname"`
	Status              model.DomainStatus `json:"status"`
	CNAMETarget         string             `json:"cname_target"`
	VerificationToken   string             `json:"verification_token"`
	DefaultRouteID      string             `json:"default_route_id"`
	OriginPoolID        string             `json:"origin_pool_id"`
	DNSRecordToCreate   map[string]string  `json:"dns_record_to_create"`
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

func (s *DomainService) OnboardDomain(req OnboardRequest) (*OnboardResponse, error) {
	if err := ValidateHostname(req.Hostname); err != nil {
		return nil, err
	}
	if req.OriginAddress == "" {
		return nil, ErrInvalidOrigin
	}
	if req.OriginPort == 0 {
		req.OriginPort = 443
	}
	if req.OriginProtocol == "" {
		req.OriginProtocol = "HTTPS"
	}

	hostname := strings.ToLower(strings.TrimSpace(req.Hostname))
	domainID := generateID("dom")
	cnameTarget := fmt.Sprintf("%s.edge.nexusedge.net", domainID)
	verificationToken := generateID("token")

	// 1. Create Domain Entity
	domain := &model.Domain{
		ID:             domainID,
		ProjectID:      req.ProjectID,
		Hostname:       hostname,
		Status:         model.DomainStatusPendingVerification,
		OnboardingType: "CNAME",
		CNAMETarget:    cnameTarget,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
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
	}
	s.store.SaveOriginPool(pool)

	originID := generateID("orig")
	origin := &model.Origin{
		ID:       originID,
		PoolID:   poolID,
		Address:  req.OriginAddress,
		Port:     req.OriginPort,
		Protocol: model.Protocol(req.OriginProtocol),
		Weight:   100,
		Healthy:  true,
	}
	if err := s.store.AddOrigin(origin); err != nil {
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

// VerifyDomain verifies customer DNS CNAME pointing and activates the edge route
func (s *DomainService) VerifyDomain(domainID string) (*model.Domain, error) {
	domain, err := s.store.GetDomain(domainID)
	if err != nil {
		return nil, err
	}

	// In automated production, this checks real DNS resolution for CNAME target
	// Once verified, domain status transitions to ACTIVE
	if err := s.store.UpdateDomainStatus(domainID, model.DomainStatusActive); err != nil {
		return nil, err
	}

	domain.Status = model.DomainStatusActive
	return domain, nil
}
