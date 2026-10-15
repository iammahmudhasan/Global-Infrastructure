package network

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

// PrintNetworkHelp prints available network subcommands.
func PrintNetworkHelp() {
	fmt.Println("NexusEdge Global Infrastructure Network Controller")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  nexusedge network <subcommand> [args] [flags]")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  bgp validate <prefix> [--sim]        Validate CIDR against RFC 7454 DFZ boundaries and bogons")
	fmt.Println("  bgp rpki <asn> <prefix>              Perform RFC 6811 Route Origin Validation (ROV)")
	fmt.Println("  bgp flap <prefix>                    Record BGP route flap penalty (RFC 2439 - Operator only)")
	fmt.Println("  bgp damping-status <prefix>          Inspect RFC 2439 decayed route damping state")
	fmt.Println("  bgp drain <peer-id> [flags]          Generate RFC 8326 Graceful Shutdown instructions (Operator only)")
	fmt.Println("  flow dispatch <src-ip> <src-port> <dst-ip> <dst-port> [proto]")
	fmt.Println("                                       Route 5-tuple flow using Maglev consistent hashing")
	fmt.Println("  maglev stats                         Display Maglev lookup table size and conntrack metrics")
	fmt.Println("  pop list                             List all 4 PoPs with live health and latency metrics")
	fmt.Println("  pop routes                           Inspect multi-region primary and failover route table")
	fmt.Println("  pop probe                            Execute real-time synthetic health probes across all PoPs")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  --sim                                Allow testbed documentation prefixes in RFC 7454 validation")
	fmt.Println("  --alternative <pop>                  Target alternative PoP for graceful BGP drain")
	fmt.Println("  --dwell <seconds>                    Dwell duration in seconds for graceful BGP drain (default: 30)")
}

// HandleNetworkCommand routes network subcommands to appropriate handlers.
func HandleNetworkCommand(client *Client, args []string) error {
	if len(args) == 0 {
		PrintNetworkHelp()
		return nil
	}

	sub := args[0]
	rest := args[1:]

	switch sub {
	case "bgp":
		return handleBGP(client, rest)
	case "flow":
		return handleFlow(client, rest)
	case "maglev":
		return handleMaglev(client, rest)
	case "pop":
		return handlePoP(client, rest)
	case "help", "--help", "-h":
		PrintNetworkHelp()
		return nil
	default:
		return fmt.Errorf("unknown network subcommand %q; run 'nexusedge network help'", sub)
	}
}

func handleBGP(client *Client, args []string) error {
	if len(args) == 0 {
		fmt.Println("Usage: nexusedge network bgp <validate|rpki|flap|damping-status|drain> [args]")
		return nil
	}

	action := args[0]
	rest := args[1:]

	switch action {
	case "validate":
		return handleBGPValidate(client, rest)
	case "rpki":
		return handleBGRPKI(client, rest)
	case "flap":
		return handleBGPFlap(client, rest)
	case "damping-status":
		return handleBGPDampingStatus(client, rest)
	case "drain":
		return handleBGPDrain(client, rest)
	default:
		return fmt.Errorf("unknown bgp action %q; valid actions: validate, rpki, flap, damping-status, drain", action)
	}
}

func handleBGPValidate(client *Client, args []string) error {
	fs := flag.NewFlagSet("bgp validate", flag.ContinueOnError)
	sim := fs.Bool("sim", false, "allow testbed prefixes")
	if err := fs.Parse(args); err != nil {
		return err
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		return fmt.Errorf("prefix argument required; usage: nexusedge network bgp validate <prefix> [--sim]")
	}
	prefix := remaining[0]

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.ValidatePrefix(ctx, prefix, *sim)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PREFIX\tSTATUS\tSTANDARD\tDETAILS")
	if resp.Status == "VALID" {
		fmt.Fprintf(w, "%s\t%s\tRFC 7454 / DFZ\tAccepted into Global Routing Table\n", resp.Prefix, resp.Status)
	} else {
		fmt.Fprintf(w, "%s\t%s\tRFC 7454 / DFZ\t%s\n", resp.Prefix, resp.Status, resp.Error)
	}
	return w.Flush()
}

func handleBGRPKI(client *Client, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("asn and prefix arguments required; usage: nexusedge network bgp rpki <asn> <prefix>")
	}

	asnVal, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return fmt.Errorf("invalid ASN: %w", err)
	}
	prefix := args[1]

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.ValidateRPKI(ctx, prefix, uint32(asnVal))
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PREFIX\tORIGIN ASN\tROV STATUS\tSTANDARD")
	fmt.Fprintf(w, "%s\tAS%d\t%s\tRFC 6811 / RPKI\n", resp.Prefix, resp.ASN, resp.Status)
	return w.Flush()
}

func handleBGPFlap(client *Client, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("prefix argument required; usage: nexusedge network bgp flap <prefix>")
	}
	prefix := args[0]

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.RecordFlap(ctx, prefix)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PREFIX\tSTATE\tPENALTY\tSTANDARD")
	fmt.Fprintf(w, "%s\t%s\t%.1f\tRFC 2439 Flap Damping\n", resp.Prefix, resp.State, resp.Penalty)
	return w.Flush()
}

func handleBGPDampingStatus(client *Client, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("prefix argument required; usage: nexusedge network bgp damping-status <prefix>")
	}
	prefix := args[0]

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GetDampingStatus(ctx, prefix)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PREFIX\tSTATE\tDECAYED PENALTY\tSTANDARD")
	fmt.Fprintf(w, "%s\t%s\t%.1f\tRFC 2439 Flap Damping\n", resp.Prefix, resp.State, resp.Penalty)
	return w.Flush()
}

func handleBGPDrain(client *Client, args []string) error {
	fs := flag.NewFlagSet("bgp drain", flag.ContinueOnError)
	alt := fs.String("alternative", "pop-sin-gw-02", "target alternative PoP")
	dwell := fs.Int("dwell", 30, "dwell duration in seconds")
	if err := fs.Parse(args); err != nil {
		return err
	}

	rem := fs.Args()
	if len(rem) == 0 {
		return fmt.Errorf("peer-id argument required; usage: nexusedge network bgp drain <peer-id> [--alternative <pop>] [--dwell <seconds>]")
	}
	peerID := rem[0]

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GenerateDrainPlan(ctx, peerID, *alt, *dwell)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PEER ID\tCOMMUNITY\tLOCAL PREF\tMED\tDWELL\tTARGET ALT")
	fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\t%s\n",
		resp.PeerID, resp.CommunityTag, resp.LocalPreference, resp.MED, resp.DwellDuration, resp.TargetAlternative)
	return w.Flush()
}

func handleFlow(client *Client, args []string) error {
	if len(args) == 0 {
		fmt.Println("Usage: nexusedge network flow dispatch <src-ip> <src-port> <dst-ip> <dst-port> [proto]")
		return nil
	}

	if args[0] != "dispatch" {
		return fmt.Errorf("unknown flow action %q; valid action: dispatch", args[0])
	}

	rem := args[1:]
	if len(rem) < 4 {
		return fmt.Errorf("insufficient arguments; usage: nexusedge network flow dispatch <src-ip> <src-port> <dst-ip> <dst-port> [proto]")
	}

	srcIP := rem[0]
	srcPort, err := strconv.ParseUint(rem[1], 10, 16)
	if err != nil {
		return fmt.Errorf("invalid src-port: %w", err)
	}
	dstIP := rem[2]
	dstPort, err := strconv.ParseUint(rem[3], 10, 16)
	if err != nil {
		return fmt.Errorf("invalid dst-port: %w", err)
	}

	var proto uint8 = 6 // TCP
	if len(rem) >= 5 {
		p, err := strconv.ParseUint(rem[4], 10, 8)
		if err == nil && p > 0 {
			proto = uint8(p)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.DispatchFlow(ctx, srcIP, uint16(srcPort), dstIP, uint16(dstPort), proto)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "FLOW\tASSIGNED BACKEND\tENDPOINT\tWEIGHT")
	flowStr := fmt.Sprintf("%s:%d -> %s:%d (proto:%d)", srcIP, srcPort, dstIP, dstPort, proto)
	endpointStr := fmt.Sprintf("%s:%d", resp.BackendIP, resp.BackendPort)
	fmt.Fprintf(w, "%s\t%s\t%s\t%d\n", flowStr, resp.BackendID, endpointStr, resp.Weight)
	return w.Flush()
}

func handleMaglev(client *Client, args []string) error {
	if len(args) == 0 || args[0] != "stats" {
		fmt.Println("Usage: nexusedge network maglev stats")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GetMaglevStats(ctx)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "RING SIZE (M)\tBACKENDS\tACTIVE CONNTRACK FLOWS\tALGORITHM")
	fmt.Fprintf(w, "%d\t%d\t%d\tGoogle Maglev Consistent Hashing\n",
		resp.TableSize, resp.BackendCount, resp.ConntrackEntries)
	return w.Flush()
}

func handlePoP(client *Client, args []string) error {
	if len(args) == 0 {
		fmt.Println("Usage: nexusedge network pop <list|routes|probe> [args]")
		return nil
	}

	action := args[0]
	switch action {
	case "list":
		return handlePoPList(client)
	case "routes":
		return handlePoPRoutes(client)
	case "probe":
		return handlePoPProbe(client)
	default:
		return fmt.Errorf("unknown pop action %q; valid actions: list, routes, probe", action)
	}
}

func handlePoPList(client *Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pops, err := client.ListPoPHealth(ctx)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "POP ID\tREGION\tTARGET ENDPOINT\tSTATUS\tHEALTHY\tLAST RTT\tEWMA RTT\tFAILOVER")
	for _, p := range pops {
		failover := p.FailoverPoPID
		if failover == "" {
			failover = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%t\t%.1f ms\t%.1f ms\t%s\n",
			p.PoPID, p.Region, p.TargetEndpoint, p.Status, p.Healthy, p.LastRTTMs, p.EWMALatencyMs, failover)
	}
	return w.Flush()
}

func handlePoPRoutes(client *Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	routes, err := client.GetPoPRoutes(ctx)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "POP ID\tREGION\tPRIMARY TARGET\tSLA RTT\tACTIVE TARGET\tSTATUS\tFAILOVER HOPS")
	for _, r := range routes {
		var hops []string
		for _, h := range r.FailoverTargets {
			resTag := ""
			if h.SovereigntyRestricted {
				resTag = " [SOVEREIGNTY_LOCKED]"
			}
			hops = append(hops, fmt.Sprintf("%s (%s, %.0fms)%s", h.TargetPoP, h.SubseaCable, h.SLARTTMs, resTag))
		}
		failoverSummary := strings.Join(hops, "; ")
		fmt.Fprintf(w, "%s\t%s\t%s\t%.1f ms\t%s\t%s\t%s\n",
			r.PoPID, r.Region, r.PrimaryTarget, r.PrimaryRTTMs, r.ActiveTarget, r.Status, failoverSummary)
	}
	return w.Flush()
}

func handlePoPProbe(client *Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := client.TriggerPoPProbe(ctx)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "POP ID\tTARGET ENDPOINT\tPROBE RESULT\tLATENCY\tHTTP CODE\tERROR")
	for popID, res := range results {
		resStr := "PASS"
		if !res.Success {
			resStr = "FAIL"
		}
		errStr := res.Error
		if errStr == "" {
			errStr = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%.2f ms\t%d\t%s\n",
			popID, res.Target, resStr, res.LatencyMs, res.StatusCode, errStr)
	}
	return w.Flush()
}
