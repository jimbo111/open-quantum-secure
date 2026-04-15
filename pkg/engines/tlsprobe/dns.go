package tlsprobe

import (
	"context"
	"fmt"
	"net"
)

// privateRanges contains ranges that must not be reachable from a TLS probe
// when --tls-strict is set: RFC 1918, loopback, link-local, unspecified, CGNAT,
// benchmark, IPv6 unique-local / link-local / loopback / unspecified, plus
// multicast and limited broadcast (not valid TLS destinations but could bypass
// the strict guard if omitted).
var privateRanges []*net.IPNet

func init() {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"0.0.0.0/8",           // "This" network (includes 0.0.0.0)
		"100.64.0.0/10",       // CGNAT (RFC 6598)
		"198.18.0.0/15",       // Benchmark testing (RFC 2544)
		"224.0.0.0/4",         // IPv4 multicast
		"255.255.255.255/32",  // IPv4 limited broadcast
		"::1/128",
		"::/128",
		"fc00::/7",
		"fe80::/10",
		"ff00::/8",            // IPv6 multicast
	}
	for _, cidr := range cidrs {
		_, ipNet, _ := net.ParseCIDR(cidr)
		privateRanges = append(privateRanges, ipNet)
	}
}

// isPrivateIP reports whether ip falls within a private, loopback, or link-local range.
func isPrivateIP(ip net.IP) bool {
	for _, r := range privateRanges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

// resolveAndValidate resolves hostname to IPs, validates all against private ranges
// (if denyPrivate is set), and returns the first valid IP string for connection pinning.
func resolveAndValidate(ctx context.Context, host string, denyPrivate bool) (string, error) {
	// If host is already an IP, validate directly.
	if ip := net.ParseIP(host); ip != nil {
		if denyPrivate && isPrivateIP(ip) {
			return "", fmt.Errorf("target %s is a private IP (blocked by --tls-strict)", host)
		}
		return host, nil
	}

	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return "", fmt.Errorf("DNS resolution failed for %s: %w", host, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("DNS resolution returned no addresses for %s", host)
	}

	if denyPrivate {
		for _, ipStr := range ips {
			ip := net.ParseIP(ipStr)
			if ip != nil && isPrivateIP(ip) {
				return "", fmt.Errorf("target %s resolves to private IP %s (blocked by --tls-strict)", host, ipStr)
			}
		}
	}

	return ips[0], nil
}
