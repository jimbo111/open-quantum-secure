package main

import "github.com/spf13/cobra"

// networkProbeFlagVars holds pointers to the variables bound by
// addNetworkProbeFlags. Both scanCmd and diffCmd declare these same
// locals; passing pointers via this struct keeps the helper a single
// source of truth for flag names + help text without forcing a wider
// refactor of how the RunE bodies access the values.
type networkProbeFlagVars struct {
	// TLS probe (Sprint 1+2+7+8+9)
	TLSTargets        *[]string
	TLSInsecure       *bool
	TLSStrict         *bool
	TLSDeepProbe      *bool
	TLSEnumGroups     *bool
	TLSEnumSigAlgs    *bool
	TLSDetectPref     *bool
	TLSMaxProbes      *int
	SkipTLS12Fallback *bool
	Verbose           *bool
	// CT log lookup (Sprint 3)
	CTLookupTargets *[]string
	CTLookupFromECH *bool
	NoNetwork       *bool
	// SSH probe (Sprint 4)
	SSHTargets *[]string
	SSHStrict  *bool
	// Zeek log ingestion (Sprint 5)
	ZeekSSLPath  *string
	ZeekX509Path *string
	// Suricata log ingestion (Sprint 6)
	SuricataEvePath *string
}

// addNetworkProbeFlags registers all network-engine probe flags on cmd.
// Single source of truth for flag names, defaults, and help text — the
// scan and diff subcommands call this with their respective local-var
// pointers so a help-text fix lands in both places automatically.
//
// Adding a new network engine flag requires:
//  1. A field on networkProbeFlagVars
//  2. A registration here
//  3. Local declarations in scanCmd and diffCmd to back the pointer
func addNetworkProbeFlags(cmd *cobra.Command, v networkProbeFlagVars) {
	// TLS probe
	cmd.Flags().StringSliceVar(v.TLSTargets, "tls-targets", nil, "TLS endpoints to probe for quantum-vulnerable crypto (comma-separated host:port)")
	cmd.Flags().BoolVar(v.TLSInsecure, "tls-insecure", false, "Skip TLS certificate verification when probing (use for self-signed certs)")
	cmd.Flags().BoolVar(v.TLSStrict, "tls-strict", true, "Deny TLS probe connections to private/loopback IPs (use --tls-strict=false to allow)")
	cmd.Flags().BoolVar(v.TLSDeepProbe, "deep-probe", false, "After TLS handshake, probe PQC group codepoints via raw ClientHellos (Sprint 7; requires --tls-targets)")
	cmd.Flags().BoolVar(v.TLSEnumGroups, "enumerate-groups", false, "Probe all 13 TLS SupportedGroup codepoints individually to build a full acceptance list (Sprint 8; requires --tls-targets; implies --deep-probe level of detail)")
	cmd.Flags().BoolVar(v.TLSEnumSigAlgs, "enumerate-sigalgs", false, "Probe each TLS SignatureScheme codepoint individually to detect server-supported sig algs (Sprint 8; requires --tls-targets)")
	cmd.Flags().BoolVar(v.TLSDetectPref, "detect-server-preference", false, "Offer all accepted groups simultaneously to detect the server's preferred group (Sprint 8; requires --tls-targets and --enumerate-groups or --deep-probe)")
	cmd.Flags().IntVar(v.TLSMaxProbes, "max-probes-per-target", 0, "Max TCP connections per TLS target across all probe passes (0 = default 30; set higher to allow exhaustive enumeration)")
	cmd.Flags().BoolVar(v.SkipTLS12Fallback, "skip-tls12-fallback", false, "Skip the TLS 1.2 fallback probe for PQC-capable targets (Sprint 9; by default the probe runs to detect downgrade vulnerability)")
	cmd.Flags().BoolVar(v.Verbose, "verbose", false, "Enable detailed progress logging to stderr (enum pass results, etc.)")

	// CT log lookup (Sprint 3)
	cmd.Flags().StringSliceVar(v.CTLookupTargets, "ct-lookup-targets", nil, "Hostnames to query CT logs for cert algorithm discovery (comma-separated)")
	cmd.Flags().BoolVar(v.CTLookupFromECH, "ct-lookup-from-ech", false, "Auto-query CT logs for ECH-enabled findings detected by the TLS probe")
	cmd.Flags().BoolVar(v.NoNetwork, "no-network", false, "Disable all outbound network calls (TLS probe + CT lookup)")
	cmd.Flags().BoolVar(v.NoNetwork, "offline", false, "Disable all outbound network calls (alias for --no-network)")

	// SSH probe (Sprint 4)
	cmd.Flags().StringSliceVar(v.SSHTargets, "ssh-targets", nil, "SSH endpoints to probe for quantum-vulnerable KEX methods (comma-separated host:port)")
	cmd.Flags().BoolVar(v.SSHStrict, "ssh-strict", false, "Deny SSH probe connections to private/loopback IPs (SSRF guard; analogous to --tls-strict)")

	// Zeek log ingestion (Sprint 5)
	cmd.Flags().StringVar(v.ZeekSSLPath, "zeek-ssl-log", "", "Path to Zeek ssl.log (TSV, JSON, or .gz) for passive TLS PQC inventory")
	cmd.Flags().StringVar(v.ZeekX509Path, "zeek-x509-log", "", "Path to Zeek x509.log (TSV, JSON, or .gz) for passive certificate PQC inventory")

	// Suricata log ingestion (Sprint 6)
	cmd.Flags().StringVar(v.SuricataEvePath, "suricata-eve", "", "Path to Suricata eve.json (plain or .gz) for passive TLS PQC inventory")
}
