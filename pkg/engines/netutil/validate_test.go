package netutil

import (
	"context"
	"net"
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	cases := []struct {
		ip      string
		private bool
	}{
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.1", true},
		{"127.0.0.1", true},
		{"169.254.0.1", true},
		{"::1", true},
		{"fe80::1", true},
		{"fc00::1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"198.51.100.1", false}, // TEST-NET-2 — not in privateRanges
		{"2001:db8::1", false},  // documentation range — not in privateRanges
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("failed to parse IP %q", tc.ip)
		}
		got := IsPrivateIP(ip)
		if got != tc.private {
			t.Errorf("IsPrivateIP(%q) = %v; want %v", tc.ip, got, tc.private)
		}
	}
}

func TestResolveAndValidate_IPLiteral_Public(t *testing.T) {
	ip, err := ResolveAndValidate(context.Background(), "8.8.8.8", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "8.8.8.8" {
		t.Errorf("got %q; want 8.8.8.8", ip)
	}
}

func TestResolveAndValidate_IPLiteral_Private_NotDenied(t *testing.T) {
	ip, err := ResolveAndValidate(context.Background(), "192.168.1.1", false)
	if err != nil {
		t.Fatalf("unexpected error when denyPrivate=false: %v", err)
	}
	if ip != "192.168.1.1" {
		t.Errorf("got %q; want 192.168.1.1", ip)
	}
}

func TestResolveAndValidate_IPLiteral_Private_Denied(t *testing.T) {
	_, err := ResolveAndValidate(context.Background(), "192.168.1.1", true)
	if err == nil {
		t.Fatal("expected error for private IP with denyPrivate=true, got nil")
	}
}

func TestResolveAndValidate_IPLiteral_Loopback_Denied(t *testing.T) {
	_, err := ResolveAndValidate(context.Background(), "127.0.0.1", true)
	if err == nil {
		t.Fatal("expected error for loopback with denyPrivate=true, got nil")
	}
}

func TestResolveAndValidate_Localhost_Denied(t *testing.T) {
	// localhost resolves to 127.0.0.1 — should be blocked by denyPrivate=true.
	_, err := ResolveAndValidate(context.Background(), "localhost", true)
	if err == nil {
		t.Fatal("expected error for localhost (resolves to loopback) with denyPrivate=true, got nil")
	}
}
