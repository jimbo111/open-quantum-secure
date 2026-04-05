package tlsprobe

import (
	"context"
	"fmt"
	"net"
)

// privateRanges contains RFC 1918, loopback, link-local, and IPv6 private ranges.
var privateRanges []*net.IPNet

func init() {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"0.0.0.0/8",      // "This" network (includes 0.0.0.0)
		"100.64.0.0/10",   // CGNAT (RFC 6598)
		"198.18.0.0/15",   // Benchmark testing (RFC 2544)
		"::1/128",
		"::/128",
		"fc00::/7",
		"fe80::/10",
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
