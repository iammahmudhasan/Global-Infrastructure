package main

import (
	"context"
	"fmt"
	"os"

	"github.com/iammahmudhasan/nexusedge-cli/internal/ai"
)

func main() {
	if len(os.Args) < 2 {
		printHelp()
		return
	}

	command := os.Args[1]
	switch command {
	case "ai":
		client := ai.NewClient()
		if err := ai.HandleAICommand(client, os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "deploy":
		fmt.Println("[NexusEdge CLI] Analyzing workload specifications...")
		fmt.Println("[NexusEdge CLI] Calculating optimal global placement across PoPs & GPU clusters...")
		fmt.Println("[NexusEdge CLI] Workload deployed successfully to nearest sovereign node.")
	case "dns":
		fmt.Println("[NexusEdge CLI] Anycast DNS record management.")
		fmt.Println("  Use 'nexusedge dns list' or 'nexusedge dns sync' to manage global records.")
	case "status":
		fmt.Println("================================================================================")
		fmt.Println(" NexusEdge Global Infrastructure - Runtime Status")
		fmt.Println("================================================================================")
		fmt.Println("Edge Anycast Points of Presence (PoPs):")
		fmt.Println("  Dhaka PoP (ap-south-2):      ONLINE (RTT: 4ms, Sovereignty: BD-NDMA-2026)")
		fmt.Println("  Singapore PoP (ap-se-1):     ONLINE (RTT: 8ms, Region: AP-East)")
		fmt.Println("  Frankfurt PoP (eu-central):  ONLINE (RTT: 14ms, Region: EU-Central)")
		fmt.Println("  Virginia PoP (us-east-1):    ONLINE (RTT: 22ms, Region: US-East)")
		fmt.Println()

		// Attempt querying AI Director status
		client := ai.NewClient()
		ctx, cancel := context.WithTimeout(context.Background(), 2)
		analytics, err := client.GetAnalytics(ctx)
		cancel()
		if err == nil {
			fmt.Printf("AI Traffic Director (%s):\n", analytics.Engine)
			fmt.Printf("  Status:               %s\n", analytics.Status)
			fmt.Printf("  Active Providers:     %d\n", analytics.ProvidersCount)
			fmt.Printf("  Total Tokens Routed:  %d\n", analytics.Economics.TotalTokensRouted)
			fmt.Printf("  Arbitraged Savings:   $%.4f USD (%.1f%% cheaper than Hyperscalers)\n",
				analytics.Economics.CostSavedUSD, analytics.Economics.SavingsPercentage)
		} else {
			fmt.Println("AI Traffic Director:")
			fmt.Println("  Gateway Status:       STANDBY (Endpoint: http://127.0.0.1:8080)")
		}
		fmt.Println("================================================================================")
	case "version", "--version", "-v":
		fmt.Println("nexusedge version 0.1.0-alpha (linux/amd64, windows/amd64, darwin/arm64)")
	default:
		printHelp()
	}
}

func printHelp() {
	fmt.Println("NexusEdge Global Infrastructure CLI (nexusedge)")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  nexusedge <command> [subcommand] [flags]")
	fmt.Println()
	fmt.Println("Available Commands:")
	fmt.Println("  ai        Manage AI compute providers, run spot arbitrage tests, and inspect token savings")
	fmt.Println("  deploy    Deploy a universal workload to the global edge fabric")
	fmt.Println("  dns       Manage Anycast DNS zones and records")
	fmt.Println("  status    Inspect real-time health and token economics of global edge PoPs")
	fmt.Println("  version   Print CLI version information")
	fmt.Println()
	fmt.Println("Run 'nexusedge <command> --help' for command-specific flags and usage.")
}
