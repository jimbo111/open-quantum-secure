// Package netutil provides shared network validation helpers used by Tier 5
// network engines. Centralising here avoids duplicating the private-IP and
// DNS-resolution logic across tlsprobe, sshprobe, and future network engines.
package netutil

import (
	"context"
	"fmt"
	"net"
)

var privateRanges []*net.IPNet

func init() {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"0.0.0.0/8",          // "This" network (includes 0.0.0.0)
		"100.64.0.0/10",      // CGNAT (RFC 6598)
		"198.18.0.0/15",      // Benchmark testing (RFC 2544)
		"224.0.0.0/4",        // IPv4 multicast
		"255.255.255.255/32", // IPv4 limited broadcast
		"::1/128",
		"::/128",
		"fc00::/7",
		"fe80::/10",
		"ff00::/8", // IPv6 multicast
	}
	for _, cidr := range cidrs {
		_, ipNet, _ := net.ParseCIDR(cidr)
		privateRanges = append(privateRanges, ipNet)
	}
}

// IsPrivateIP reports whether ip falls within a private, loopback, or link-local range.
func IsPrivateIP(ip net.IP) bool {
	for _, r := range privateRanges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

// ResolveAndValidate resolves hostname to IPs, validates all resolved addresses
// against private/loopback/link-local ranges (when denyPrivate is set), and
// returns the first valid IP string for DNS-pinned connection establishment.
//
// When host is already an IP literal, DNS resolution is skipped and the IP is
// validated directly. The denyPrivate flag maps to --ssh-strict on the CLI.
func ResolveAndValidate(ctx context.Context, host string, denyPrivate bool) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		if denyPrivate && IsPrivateIP(ip) {
			return "", fmt.Errorf("target %s is a private IP (blocked by --ssh-strict)", host)
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
			if ip != nil && IsPrivateIP(ip) {
				return "", fmt.Errorf("target %s resolves to private IP %s (blocked by --ssh-strict)", host, ipStr)
			}
		}
	}

	return ips[0], nil
}
