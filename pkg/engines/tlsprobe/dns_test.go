package tlsprobe

import (
	"context"
	"net"
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip      string
		private bool
	}{
		// RFC 1918
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"192.168.255.255", true},
		// Loopback
		{"127.0.0.1", true},
		{"127.255.255.255", true},
		// Link-local
		{"169.254.0.1", true},
		{"169.254.255.255", true},
		// IPv6
		{"::1", true},
		{"fc00::1", true},
		{"fe80::1", true},
		// Unspecified addresses
		{"0.0.0.0", true},
		{"::", true},
		// Public IPs
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"93.184.216.34", false},
		{"2607:f8b0:4004:800::200e", false},
		// Edge: 172.15.x.x is NOT private (before /12 range)
		{"172.15.255.255", false},
		// Edge: 172.32.x.x is NOT private (after /12 range)
		{"172.32.0.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %q", tt.ip)
			}
			got := isPrivateIP(ip)
			if got != tt.private {
				t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, got, tt.private)
			}
		})
	}
}

func TestResolveAndValidate_DirectIP(t *testing.T) {
	ctx := context.Background()

	// Public IP should pass regardless of denyPrivate.
	ip, err := resolveAndValidate(ctx, "8.8.8.8", true)
	if err != nil {
		t.Fatalf("unexpected error for public IP: %v", err)
	}
	if ip != "8.8.8.8" {
		t.Errorf("got ip=%q, want 8.8.8.8", ip)
	}

	// Private IP should fail when denyPrivate=true.
	_, err = resolveAndValidate(ctx, "10.0.0.1", true)
	if err == nil {
		t.Error("expected error for private IP with denyPrivate=true")
	}

	// Private IP should pass when denyPrivate=false.
	ip, err = resolveAndValidate(ctx, "10.0.0.1", false)
	if err != nil {
		t.Fatalf("unexpected error for private IP with denyPrivate=false: %v", err)
	}
	if ip != "10.0.0.1" {
		t.Errorf("got ip=%q, want 10.0.0.1", ip)
	}
}

func TestResolveAndValidate_EmptyHost(t *testing.T) {
	ctx := context.Background()
	_, err := resolveAndValidate(ctx, "", false)
	if err == nil {
		t.Error("expected error for empty host")
	}
}
