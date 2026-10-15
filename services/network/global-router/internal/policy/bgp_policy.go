package policy

import (
	"errors"
	"fmt"
	"math"
	"net"
	"sync"
	"time"
)

var (
	ErrPrefixInvalid        = errors.New("invalid CIDR prefix format")
	ErrPrefixTooSpecific    = errors.New("prefix length exceeds RFC 7454 maximum allowed length")
	ErrPrefixTooBroad       = errors.New("prefix length is too broad for global routing")
	ErrBogonPrefixRejected  = errors.New("bogon prefix rejected under RFC 6890 / RFC 7454")
	ErrRouteSuppressed      = errors.New("route is currently suppressed by BGP route flap damping")
	ErrDampingParamsInvalid = errors.New("invalid flap damping configuration parameters")
)

// RFC 7454 (BGP Operations and Security) Global DFZ Prefix Boundaries
const (
	MinIPv4PrefixLen = 8
	MaxIPv4PrefixLen = 24 // RFC 7454 Section 5.1: Tier-1 DFZ drops > /24
	MinIPv6PrefixLen = 16
	MaxIPv6PrefixLen = 48 // RFC 7454 Section 5.2: Tier-1 DFZ drops > /48

	// RFC 8326 BGP Graceful Shutdown Well-Known Community
	CommunityGracefulShutdown = "65535:0"
)

// Bogon CIDRs under RFC 6890 / RFC 5735 / RFC 5156 (unroutable in public DFZ)
var bogonIPv4Prefixes = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24", // RFC 5737 TEST-NET-2
	"203.0.113.0/24",  // RFC 5737 TEST-NET-3
	"224.0.0.0/4",     // Multicast
	"240.0.0.0/4",     // Reserved
}

var bogonIPv6Prefixes = []string{
	"::/128",
	"::1/128",
	"2001:db8::/32", // RFC 3849 Documentation
	"fc00::/7",      // ULA
	"fe80::/10",     // Link-Local
	"ff00::/8",      // Multicast
}

// PrefixSanitizer validates and filters BGP routes according to RFC 7454.
type PrefixSanitizer struct {
	bogonNets []*net.IPNet
}

func NewPrefixSanitizer() *PrefixSanitizer {
	var nets []*net.IPNet
	for _, cidr := range append(bogonIPv4Prefixes, bogonIPv6Prefixes...) {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			nets = append(nets, ipNet)
		}
	}
	return &PrefixSanitizer{bogonNets: nets}
}

// ValidateAdvertisedPrefix checks whether a prefix complies with RFC 7454 DFZ standards.
// In simulation mode (e.g. documentation testbeds under RFC 5737 / RFC 3849), test bogons are permitted.
func (ps *PrefixSanitizer) ValidateAdvertisedPrefix(cidr string, isSimulation bool) error {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrPrefixInvalid, cidr)
	}

	ones, bits := ipNet.Mask.Size()
	isIPv4 := bits == 32

	if isIPv4 {
		if ones > MaxIPv4PrefixLen {
			return fmt.Errorf("%w: IPv4 /%d exceeds RFC 7454 limit of /%d", ErrPrefixTooSpecific, ones, MaxIPv4PrefixLen)
		}
		if ones < MinIPv4PrefixLen {
			return fmt.Errorf("%w: IPv4 /%d is broader than allowed /%d", ErrPrefixTooBroad, ones, MinIPv4PrefixLen)
		}
	} else {
		if ones > MaxIPv6PrefixLen {
			return fmt.Errorf("%w: IPv6 /%d exceeds RFC 7454 limit of /%d", ErrPrefixTooSpecific, ones, MaxIPv6PrefixLen)
		}
		if ones < MinIPv6PrefixLen {
			return fmt.Errorf("%w: IPv6 /%d is broader than allowed /%d", ErrPrefixTooBroad, ones, MinIPv6PrefixLen)
		}
	}

	if !isSimulation {
		for _, bogon := range ps.bogonNets {
			if bogon.Contains(ip) || ipNet.Contains(bogon.IP) {
				return fmt.Errorf("%w: %s overlaps with reserved bogon %s", ErrBogonPrefixRejected, cidr, bogon.String())
			}
		}
	}

	return nil
}

// RPKIValidationStatus represents the result of RFC 6811 Route Origin Validation.
type RPKIValidationStatus string

const (
	RPKIValid    RPKIValidationStatus = "VALID"
	RPKIInvalid  RPKIValidationStatus = "INVALID"
	RPKINotFound RPKIValidationStatus = "NOT_FOUND"
)

// ROAEntry defines a Route Origin Authorization record under RFC 6482 / RFC 6811.
type ROAEntry struct {
	Prefix    *net.IPNet
	MaxLen    int
	OriginASN uint32
}

// RPKIRouteOriginValidator performs RFC 6811 ROV checks on BGP route announcements.
type RPKIRouteOriginValidator struct {
	mu   sync.RWMutex
	roas []ROAEntry
}

func NewRPKIRouteOriginValidator() *RPKIRouteOriginValidator {
	return &RPKIRouteOriginValidator{
		roas: make([]ROAEntry, 0),
	}
}

func (v *RPKIRouteOriginValidator) AddROA(cidr string, maxLen int, originASN uint32) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	ones, _ := ipNet.Mask.Size()
	if maxLen < ones {
		return fmt.Errorf("maxLen %d cannot be smaller than prefix length %d", maxLen, ones)
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	v.roas = append(v.roas, ROAEntry{
		Prefix:    ipNet,
		MaxLen:    maxLen,
		OriginASN: originASN,
	})
	return nil
}

// ValidateRoute validates prefix origin according to RFC 6811 Section 2.
func (v *RPKIRouteOriginValidator) ValidateRoute(cidr string, originASN uint32) (RPKIValidationStatus, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return RPKINotFound, fmt.Errorf("%w: %s", ErrPrefixInvalid, cidr)
	}
	routeLen, _ := ipNet.Mask.Size()

	v.mu.RLock()
	defer v.mu.RUnlock()

	var coveringROAsFound bool

	for _, roa := range v.roas {
		// Check if ROA prefix covers the route prefix
		if roa.Prefix.Contains(ipNet.IP) {
			coveringROAsFound = true
			if roa.OriginASN == originASN && routeLen <= roa.MaxLen {
				return RPKIValid, nil
			}
		}
	}

	if coveringROAsFound {
		return RPKIInvalid, nil
	}

	return RPKINotFound, nil
}

// RouteState indicates the operational BGP damping state of a route.
type RouteState string

const (
	RouteStateActive     RouteState = "ACTIVE"
	RouteStateSuppressed RouteState = "DAMPED"
)

// FlapDampingConfig encapsulates parameters defined by RFC 2439.
type FlapDampingConfig struct {
	HalfLife            time.Duration // Decay half-life (e.g. 15 minutes)
	ReuseThreshold      float64       // Penalty below which route is unsuppressed (e.g. 750)
	SuppressThreshold   float64       // Penalty above which route is suppressed (e.g. 2000)
	MaxSuppressDuration time.Duration // Maximum continuous suppression duration (e.g. 60 minutes)
	FlapPenalty         float64       // Penalty added on each flap (e.g. 1000)
}

func DefaultFlapDampingConfig() FlapDampingConfig {
	return FlapDampingConfig{
		HalfLife:            15 * time.Minute,
		ReuseThreshold:      750.0,
		SuppressThreshold:   2000.0,
		MaxSuppressDuration: 60 * time.Minute,
		FlapPenalty:         1000.0,
	}
}

type routeDampingState struct {
	penalty          float64
	state            RouteState
	lastFlap         time.Time
	suppressedAt     time.Time
	suppressedOrigin time.Time
}

// RouteFlapDampingGuard implements RFC 2439 BGP Route Flap Damping.
type RouteFlapDampingGuard struct {
	mu     sync.Mutex
	cfg    FlapDampingConfig
	lambda float64 // Decay constant = ln(2) / HalfLife
	routes map[string]*routeDampingState
}

func NewRouteFlapDampingGuard(cfg FlapDampingConfig) (*RouteFlapDampingGuard, error) {
	if cfg.HalfLife <= 0 || cfg.ReuseThreshold <= 0 || cfg.SuppressThreshold <= cfg.ReuseThreshold {
		return nil, ErrDampingParamsInvalid
	}
	lambda := math.Ln2 / cfg.HalfLife.Seconds()
	return &RouteFlapDampingGuard{
		cfg:    cfg,
		lambda: lambda,
		routes: make(map[string]*routeDampingState),
	}, nil
}

// RecordFlap records a route flap event and returns the new route state and current penalty.
func (g *RouteFlapDampingGuard) RecordFlap(prefix string, now time.Time) (RouteState, float64) {
	g.mu.Lock()
	defer g.mu.Unlock()

	st, exists := g.routes[prefix]
	if !exists {
		st = &routeDampingState{
			penalty:  0.0,
			state:    RouteStateActive,
			lastFlap: now,
		}
		g.routes[prefix] = st
	}

	// Apply exponential decay: P(t) = P(t0) * e^(-lambda * dt)
	elapsed := now.Sub(st.lastFlap).Seconds()
	if elapsed > 0 {
		st.penalty = st.penalty * math.Exp(-g.lambda*elapsed)
	}

	// Add flap penalty
	st.penalty += g.cfg.FlapPenalty
	st.lastFlap = now

	// Check suppression threshold
	if st.penalty >= g.cfg.SuppressThreshold && st.state != RouteStateSuppressed {
		st.state = RouteStateSuppressed
		st.suppressedAt = now
		st.suppressedOrigin = now
	}

	return st.state, st.penalty
}

// EvaluateState calculates decayed penalty and checks if a suppressed route should be unsuppressed.
func (g *RouteFlapDampingGuard) EvaluateState(prefix string, now time.Time) (RouteState, float64) {
	g.mu.Lock()
	defer g.mu.Unlock()

	st, exists := g.routes[prefix]
	if !exists {
		return RouteStateActive, 0.0
	}

	elapsed := now.Sub(st.lastFlap).Seconds()
	if elapsed > 0 {
		st.penalty = st.penalty * math.Exp(-g.lambda*elapsed)
		st.lastFlap = now
	}

	if st.state == RouteStateSuppressed {
		// Cap max suppress duration under RFC 2439 Section 4.2
		if g.cfg.MaxSuppressDuration > 0 && now.Sub(st.suppressedOrigin) >= g.cfg.MaxSuppressDuration {
			st.state = RouteStateActive
			st.penalty = g.cfg.ReuseThreshold * 0.9
			return st.state, st.penalty
		}

		// Hysteresis reuse check
		if st.penalty <= g.cfg.ReuseThreshold {
			st.state = RouteStateActive
		}
	}

	return st.state, st.penalty
}

// GracefulDrainPlan encapsulates RFC 8326 Graceful BGP Shutdown instructions.
type GracefulDrainPlan struct {
	PeerID            string        `json:"peer_id"`
	CommunityTag      string        `json:"community_tag"`
	LocalPreference   int           `json:"local_preference"`
	MED               int           `json:"med"`
	DwellDuration     time.Duration `json:"dwell_duration"`
	TargetAlternative string        `json:"target_alternative"`
}

// GenerateGracefulShutdownPlan builds a safe drain plan before taking a PoP or peer down.
func GenerateGracefulShutdownPlan(peerID, alternativePoP string, dwellDuration time.Duration) GracefulDrainPlan {
	if dwellDuration <= 0 {
		dwellDuration = 30 * time.Second
	}
	return GracefulDrainPlan{
		PeerID:            peerID,
		CommunityTag:      CommunityGracefulShutdown,
		LocalPreference:   0,     // Low local preference diverts outbound traffic
		MED:               65535, // High MED discourages inbound traffic
		DwellDuration:     dwellDuration,
		TargetAlternative: alternativePoP,
	}
}
