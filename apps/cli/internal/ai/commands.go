package ai

import (
	"context"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
)

// PrintAIHelp prints the available AI subcommands.
func PrintAIHelp() {
	fmt.Println("NexusEdge AI / Compute Traffic Controller")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  nexusedge ai <subcommand> [flags]")
	fmt.Println()
	fmt.Println("Subcommands:")
	fmt.Println("  providers list     List all registered upstream AI compute providers")
	fmt.Println("  providers add      Register a new AI provider in the Control Plane Key Vault")
	fmt.Println("  providers delete   Remove an AI provider by ID")
	fmt.Println("  analytics          Display live token volume, costs, and arbitrage dollar savings")
	fmt.Println("  test               Execute a test prompt to verify multi-strategy routing and failover")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  Run 'nexusedge ai <subcommand> --help' for details on specific flags.")
}

// HandleAICommand routes ai subcommands to appropriate handlers.
func HandleAICommand(client *Client, args []string) error {
	if len(args) == 0 {
		PrintAIHelp()
		return nil
	}

	subcommand := args[0]
	rest := args[1:]

	switch subcommand {
	case "providers":
		return handleProviders(client, rest)
	case "analytics":
		return handleAnalytics(client, rest)
	case "test":
		return handleTest(client, rest)
	case "help", "--help", "-h":
		PrintAIHelp()
		return nil
	default:
		return fmt.Errorf("unknown ai subcommand %q; run 'nexusedge ai help'", subcommand)
	}
}

func handleProviders(client *Client, args []string) error {
	if len(args) == 0 {
		fmt.Println("Usage: nexusedge ai providers <list|add|delete> [flags]")
		return nil
	}

	action := args[0]
	rest := args[1:]

	switch action {
	case "list":
		fs := flag.NewFlagSet("ai providers list", flag.ContinueOnError)
		projectID := fs.String("project-id", "proj-default", "Project identifier")
		if err := fs.Parse(rest); err != nil {
			return err
		}

		ctx := context.Background()
		providers, err := client.ListProviders(ctx, *projectID)
		if err != nil {
			return fmt.Errorf("failed to list providers: %w", err)
		}

		fmt.Printf("Registered AI Compute Providers (Project: %s, Total: %d)\n\n", *projectID, len(providers))
		if len(providers) == 0 {
			fmt.Println("No providers registered. Use 'nexusedge ai providers add' to register an upstream.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tTYPE\tENDPOINT\tCOST/1M\tJURISDICTION\tPRIORITY\tSTATUS")
		for _, p := range providers {
			status := "ENABLED"
			if !p.Enabled {
				status = "DISABLED"
			}
			jur := p.SovereigntyJurisdiction
			if jur == "" {
				jur = "GLOBAL"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t$%.2f\t%s\t%d\t%s\n",
				p.ID, p.Name, p.ProviderType, p.Endpoint, p.CostPerMTokens, jur, p.Priority, status)
		}
		return w.Flush()

	case "add":
		fs := flag.NewFlagSet("ai providers add", flag.ContinueOnError)
		id := fs.String("id", "", "Unique provider identifier (e.g. coreweave-spot-01) [required]")
		name := fs.String("name", "", "Human-readable provider name [required]")
		endpoint := fs.String("endpoint", "", "Upstream base URL endpoint [required]")
		providerType := fs.String("type", "", "Provider type: openai, azure, coreweave, vllm, onprem, aws [required]")
		apiKey := fs.String("key", "", "API Key for provider authentication (optional)")
		cost := fs.Float64("cost", 1.0, "Cost per 1M tokens in USD")
		priority := fs.Int("priority", 1, "Priority tier (lower number = higher priority)")
		jurisdiction := fs.String("jurisdiction", "", "Sovereignty jurisdiction code (e.g. BD, US, EU)")
		cooldown := fs.Int("cooldown", 10, "Circuit breaker 429 cooldown period in seconds")
		projectID := fs.String("project-id", "proj-default", "Project identifier")

		if err := fs.Parse(rest); err != nil {
			return err
		}

		if *id == "" || *name == "" || *endpoint == "" || *providerType == "" {
			return fmt.Errorf("missing required flags: --id, --name, --endpoint, and --type are required")
		}

		req := CreateAIProviderRequest{
			ID:                      *id,
			ProjectID:               *projectID,
			Name:                    *name,
			Endpoint:                *endpoint,
			ProviderType:            *providerType,
			APIKey:                  *apiKey,
			CostPerMTokens:          *cost,
			Priority:                *priority,
			SovereigntyJurisdiction: *jurisdiction,
			FailoverCooldownSecs:    *cooldown,
			Enabled:                 true,
		}

		ctx := context.Background()
		created, err := client.AddProvider(ctx, req)
		if err != nil {
			return fmt.Errorf("failed to register provider: %w", err)
		}

		fmt.Printf("Provider registered successfully in Key Vault:\n")
		fmt.Printf("  ID:           %s\n", created.ID)
		fmt.Printf("  Name:         %s\n", created.Name)
		fmt.Printf("  Type:         %s\n", created.ProviderType)
		fmt.Printf("  Endpoint:     %s\n", created.Endpoint)
		fmt.Printf("  Cost/1M:      $%.2f\n", created.CostPerMTokens)
		fmt.Printf("  Jurisdiction: %s\n", created.SovereigntyJurisdiction)
		fmt.Printf("  Priority:     %d\n", created.Priority)
		return nil

	case "delete":
		fs := flag.NewFlagSet("ai providers delete", flag.ContinueOnError)
		id := fs.String("id", "", "Provider ID to remove [required]")
		if err := fs.Parse(rest); err != nil {
			return err
		}

		if *id == "" {
			return fmt.Errorf("missing required flag: --id is required")
		}

		ctx := context.Background()
		if err := client.DeleteProvider(ctx, *id); err != nil {
			return fmt.Errorf("failed to delete provider: %w", err)
		}
		fmt.Printf("Provider %q deleted successfully from Key Vault.\n", *id)
		return nil

	default:
		return fmt.Errorf("unknown action %q for providers; run 'nexusedge ai providers'", action)
	}
}

func handleAnalytics(client *Client, args []string) error {
	ctx := context.Background()
	analytics, err := client.GetAnalytics(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve live analytics: %w", err)
	}

	fmt.Println("================================================================================")
	fmt.Println(" NexusEdge Universal AI Traffic Director - Live Economics & Health")
	fmt.Println("================================================================================")
	fmt.Printf("Status:               %s\n", analytics.Status)
	fmt.Printf("Director Engine:      %s\n", analytics.Engine)
	fmt.Printf("Snapshot Timestamp:   %s\n", analytics.Timestamp)
	fmt.Println()
	fmt.Println("--- Real-Time Economics Summary ---")
	fmt.Printf("  Total Tokens Routed:       %d\n", analytics.Economics.TotalTokensRouted)
	fmt.Printf("  Prompt / Completion:       %d / %d\n", analytics.Economics.PromptTokens, analytics.Economics.CompletionTokens)
	fmt.Printf("  Actual Cost Spent:         $%.4f USD\n", analytics.Economics.CostSpentUSD)
	fmt.Printf("  Arbitraged Dollar Savings: $%.4f USD\n", analytics.Economics.CostSavedUSD)
	fmt.Printf("  Cost Savings Percentage:   %.1f%%\n", analytics.Economics.SavingsPercentage)
	fmt.Println()

	fmt.Println("--- Connected Compute Providers Telemetry ---")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ID\tTYPE\tJURISDICTION\tREQS\t429S\tFAILOVERS\tTTFT(ms)\tCOST/1M\tHEALTH")
	for _, p := range analytics.Providers {
		health := "HEALTHY"
		if !p.IsAvailable {
			health = "BACKOFF_COOLDOWN"
		}
		jur := p.Jurisdiction
		if jur == "" {
			jur = "GLOBAL"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%d\t%.1f\t$%.2f\t%s\n",
			p.ID, p.Type, jur, p.TotalRequests, p.RateLimited429, p.FailoversTriggered, p.AvgTTFTMs, p.CostPerMTokens, health)
	}
	w.Flush()
	fmt.Println("================================================================================")
	return nil
}

func handleTest(client *Client, args []string) error {
	fs := flag.NewFlagSet("ai test", flag.ContinueOnError)
	model := fs.String("model", "llama-3.3-70b", "Model identifier to request")
	prompt := fs.String("prompt", "Where should this AI workload run right now?", "Input prompt to test")
	strategy := fs.String("strategy", "cost", "Routing strategy: cost, latency, balanced, priority")
	jurisdiction := fs.String("jurisdiction", "", "Sovereignty jurisdiction filter (e.g. BD, US, EU)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	fmt.Println("Executing test inference dispatch via NexusEdge Universal AI Director...")
	fmt.Printf("  Model:        %s\n", *model)
	fmt.Printf("  Strategy:     %s\n", *strategy)
	if *jurisdiction != "" {
		fmt.Printf("  Jurisdiction: %s\n", *jurisdiction)
	}
	fmt.Printf("  Prompt:       %q\n", *prompt)
	fmt.Println()

	ctx := context.Background()
	result, err := client.TestInference(ctx, *model, *prompt, *strategy, *jurisdiction)
	if err != nil {
		return fmt.Errorf("test dispatch failed: %w", err)
	}

	fmt.Println("--- Inference Dispatch Results ---")
	fmt.Printf("  HTTP Status:               %d\n", result.StatusCode)
	fmt.Printf("  Selected Compute Provider: %s\n", result.ProviderID)
	fmt.Printf("  Active Routing Strategy:   %s\n", result.RoutingStrategy)
	if result.CostPerMTokens != "" {
		fmt.Printf("  Provider Cost / 1M Tokens: $%s\n", result.CostPerMTokens)
	}
	if result.TokensTotal != "" {
		fmt.Printf("  Total Tokens Extracted:    %s\n", result.TokensTotal)
	}
	if result.EstimatedSavingsUSD != "" {
		fmt.Printf("  Estimated Dollar Savings:  $%s USD\n", result.EstimatedSavingsUSD)
	}
	fmt.Printf("  Time To First Token (TTFT): %s ms\n", result.TTFTMs)
	fmt.Printf("  Transparent Failovers:     %s\n", result.FailoverCount)
	fmt.Printf("  Total End-to-End Duration: %s ms\n", result.TotalDurationMs)
	fmt.Println()
	fmt.Println("--- Upstream Response Preview ---")
	fmt.Println(result.ResponseContent)
	fmt.Println("---------------------------------")
	return nil
}
