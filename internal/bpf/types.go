package bpf

import "net/netip"

const (
	// ModeAudit records would-be denials without blocking traffic.
	ModeAudit uint32 = 0
	// ModeEnforce blocks traffic that does not match the active allowlist.
	ModeEnforce uint32 = 1
)

// Rule is a protocol and port allowlist entry for an IPv4 prefix.
type Rule struct {
	Prefix   netip.Prefix
	Protocol uint8
	Ports    []uint16
}

// Event represents a would-be or enforced denial emitted by the kernel.
type Event struct {
	CgroupID uint64
	Address  netip.Addr
	Port     uint16
	Protocol uint8
	Hook     uint8
	Denied   bool
}
