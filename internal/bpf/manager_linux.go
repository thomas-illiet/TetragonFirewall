//go:build linux

package bpf

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// Manager owns loaded eBPF objects, pinned state, and cgroup attachments.
type Manager struct {
	mu      sync.Mutex
	objects FirewallObjects
	pinRoot string
	links   map[string][]link.Link
	reader  *ringbuf.Reader
}

// NewManager loads the embedded eBPF collection and reuses compatible pinned maps.
func NewManager(pinRoot string) (*Manager, error) {
	if err := os.MkdirAll(filepath.Join(pinRoot, "maps"), 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(pinRoot, "programs"), 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(pinRoot, "links"), 0o755); err != nil {
		return nil, err
	}

	spec, err := LoadFirewall()
	if err != nil {
		return nil, fmt.Errorf("load embedded BPF spec: %w", err)
	}
	replacements := map[string]*ebpf.Map{}
	for _, name := range []string{"cidrs_a", "cidrs_b", "rules_a", "rules_b", "active_config", "counters", "events"} {
		pinned, err := ebpf.LoadPinnedMap(filepath.Join(pinRoot, "maps", name), nil)
		if err == nil {
			replacements[name] = pinned
		} else if !errors.Is(err, os.ErrNotExist) {
			closeMaps(replacements)
			return nil, fmt.Errorf("load pinned map %s: %w", name, err)
		}
	}
	var objects FirewallObjects
	if err := spec.LoadAndAssign(&objects, &ebpf.CollectionOptions{MapReplacements: replacements}); err != nil {
		closeMaps(replacements)
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}
	closeMaps(replacements)
	m := &Manager{objects: objects, pinRoot: pinRoot, links: map[string][]link.Link{}}
	if err := m.pinObjects(); err != nil {
		m.Close()
		return nil, err
	}
	m.reader, err = ringbuf.NewReader(m.objects.Events)
	if err != nil {
		m.Close()
		return nil, fmt.Errorf("open event ring buffer: %w", err)
	}
	return m, nil
}

// closeMaps closes every map handle in a replacement set.
func closeMaps(maps map[string]*ebpf.Map) {
	for _, m := range maps {
		_ = m.Close()
	}
}

// pinObjects persists maps and the current program versions in bpffs.
func (m *Manager) pinObjects() error {
	maps := map[string]*ebpf.Map{
		"cidrs_a": m.objects.CidrsA, "cidrs_b": m.objects.CidrsB,
		"rules_a": m.objects.RulesA, "rules_b": m.objects.RulesB,
		"active_config": m.objects.ActiveConfig, "counters": m.objects.Counters,
		"events": m.objects.Events,
	}
	for name, object := range maps {
		path := filepath.Join(m.pinRoot, "maps", name)
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			if err := object.Pin(path); err != nil {
				return fmt.Errorf("pin map %s: %w", name, err)
			}
		}
	}
	programs := map[string]*ebpf.Program{
		"connect4": m.objects.Connect4, "sendmsg4": m.objects.Sendmsg4,
		"egress_filter": m.objects.EgressFilter,
	}
	for name, program := range programs {
		path := filepath.Join(m.pinRoot, "programs", name)
		_ = os.Remove(path)
		if err := program.Pin(path); err != nil {
			return fmt.Errorf("pin program %s: %w", name, err)
		}
	}
	return nil
}

// Apply writes a complete inactive rule generation and activates it atomically.
func (m *Manager) Apply(rules []Rule, mode uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var current FirewallConfigValue
	zero := uint32(0)
	if err := m.objects.ActiveConfig.Lookup(zero, &current); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("read active generation: %w", err)
	}
	next := uint32(1)
	cidrs, ports := m.objects.CidrsB, m.objects.RulesB
	if current.Generation == 1 {
		next, cidrs, ports = 0, m.objects.CidrsA, m.objects.RulesA
	}
	if err := clearCIDRMap(cidrs); err != nil {
		return fmt.Errorf("clear CIDR map: %w", err)
	}
	if err := clearRuleMap(ports); err != nil {
		return fmt.Errorf("clear rule map: %w", err)
	}

	groups := map[netip.Prefix]uint32{}
	sorted := append([]Rule(nil), rules...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Prefix.String() < sorted[j].Prefix.String() })
	for _, rule := range sorted {
		if !rule.Prefix.Addr().Is4() {
			return fmt.Errorf("non-IPv4 rule %s", rule.Prefix)
		}
		group, ok := groups[rule.Prefix.Masked()]
		if !ok {
			group = uint32(len(groups) + 1)
			groups[rule.Prefix.Masked()] = group
			addr := rule.Prefix.Masked().Addr().As4()
			key := FirewallLpmKey{PrefixLen: uint32(rule.Prefix.Bits()), Addr: binary.LittleEndian.Uint32(addr[:])}
			if err := cidrs.Update(key, group, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("insert CIDR %s: %w", rule.Prefix, err)
			}
		}
		for _, port := range rule.Ports {
			key := FirewallRuleKey{Group: group, Port: port, Protocol: rule.Protocol}
			allow := uint8(1)
			if err := ports.Update(key, allow, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("insert rule %s protocol=%d port=%d: %w", rule.Prefix, rule.Protocol, port, err)
			}
		}
	}
	config := FirewallConfigValue{Generation: next, Mode: mode}
	if err := m.objects.ActiveConfig.Update(zero, config, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("activate generation: %w", err)
	}
	return nil
}

// clearCIDRMap removes every entry from an LPM trie map.
func clearCIDRMap(m *ebpf.Map) error {
	var key FirewallLpmKey
	var value uint32
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return iter.Err()
}

// clearRuleMap removes every entry from a protocol and port rule map.
func clearRuleMap(m *ebpf.Map) error {
	var key FirewallRuleKey
	var value uint8
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return iter.Err()
}

// Attach attaches and pins all firewall programs for one container cgroup.
func (m *Manager) Attach(identity, cgroupPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := linkKey(identity)
	if _, ok := m.links[key]; ok {
		return nil
	}
	loaded := make([]link.Link, 0, 3)
	allPinned := true
	for _, suffix := range []string{"connect4", "sendmsg4", "egress"} {
		l, err := link.LoadPinnedLink(filepath.Join(m.pinRoot, "links", key+"-"+suffix), nil)
		if err != nil {
			allPinned = false
			break
		}
		loaded = append(loaded, l)
	}
	if allPinned {
		m.links[key] = loaded
		return nil
	}
	for _, l := range loaded {
		_ = l.Close()
	}
	for _, suffix := range []string{"connect4", "sendmsg4", "egress"} {
		_ = os.Remove(filepath.Join(m.pinRoot, "links", key+"-"+suffix))
	}

	types := []struct {
		name    string
		attach  ebpf.AttachType
		program *ebpf.Program
	}{
		{"connect4", ebpf.AttachCGroupInet4Connect, m.objects.Connect4},
		{"sendmsg4", ebpf.AttachCGroupUDP4Sendmsg, m.objects.Sendmsg4},
		{"egress", ebpf.AttachCGroupInetEgress, m.objects.EgressFilter},
	}
	for _, item := range types {
		l, err := link.AttachCgroup(link.CgroupOptions{Path: cgroupPath, Attach: item.attach, Program: item.program})
		if err != nil {
			closeLinks(loaded, true)
			return fmt.Errorf("attach %s to %s: %w", item.name, cgroupPath, err)
		}
		if err := l.Pin(filepath.Join(m.pinRoot, "links", key+"-"+item.name)); err != nil {
			_ = l.Close()
			closeLinks(loaded, true)
			return fmt.Errorf("pin %s link: %w", item.name, err)
		}
		loaded = append(loaded, l)
	}
	m.links[key] = loaded
	return nil
}

// ReconcileLinks removes pinned cgroup links that are no longer desired.
func (m *Manager) ReconcileLinks(desired map[string]struct{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	entries, err := os.ReadDir(filepath.Join(m.pinRoot, "links"))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		key := strings.SplitN(entry.Name(), "-", 2)[0]
		if _, ok := desired[key]; ok {
			continue
		}
		if links, ok := m.links[key]; ok {
			closeLinks(links, true)
			delete(m.links, key)
		}
		_ = os.Remove(filepath.Join(m.pinRoot, "links", entry.Name()))
	}
	return nil
}

// closeLinks optionally unpins links before closing their userspace handles.
func closeLinks(links []link.Link, unpin bool) {
	for _, l := range links {
		if unpin {
			_ = l.Unpin()
		}
		_ = l.Close()
	}
}

// linkKey returns the stable bpffs key used for a container identity.
func linkKey(identity string) string {
	sum := sha256.Sum256([]byte(identity))
	return fmt.Sprintf("%x", sum[:12])
}

// LinkKey returns the stable bpffs key used for a container identity.
func (m *Manager) LinkKey(identity string) string { return linkKey(identity) }

// ReadEvent blocks until the next firewall decision event is available.
func (m *Manager) ReadEvent() (Event, error) {
	record, err := m.reader.Read()
	if err != nil {
		return Event{}, err
	}
	if len(record.RawSample) < 24 {
		return Event{}, fmt.Errorf("short event: %d bytes", len(record.RawSample))
	}
	b := record.RawSample
	addrBytes := [4]byte{}
	binary.LittleEndian.PutUint32(addrBytes[:], binary.LittleEndian.Uint32(b[8:12]))
	return Event{
		CgroupID: binary.LittleEndian.Uint64(b[0:8]),
		Address:  netip.AddrFrom4(addrBytes),
		Port:     binary.LittleEndian.Uint16(b[12:14]),
		Protocol: b[14], Hook: b[15], Denied: b[16] != 0,
	}, nil
}

// Counters aggregates per-CPU allow and deny counters.
func (m *Manager) Counters() ([4]uint64, error) {
	var result [4]uint64
	for key := uint32(0); key < 4; key++ {
		var perCPU []uint64
		if err := m.objects.Counters.Lookup(key, &perCPU); err != nil {
			return result, err
		}
		for _, value := range perCPU {
			result[key] += value
		}
	}
	return result, nil
}

// Close releases userspace handles while preserving pinned kernel state.
func (m *Manager) Close() error {
	if m.reader != nil {
		_ = m.reader.Close()
	}
	for _, links := range m.links {
		closeLinks(links, false)
	}
	return m.objects.Close()
}

// CleanupPins removes this manager's persistent objects. It is intended for
// preflight runs and explicit uninstall workflows, never normal shutdown.
func (m *Manager) CleanupPins() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cleanRoot := filepath.Clean(m.pinRoot)
	if cleanRoot == "/" || cleanRoot == "." || cleanRoot == "/sys/fs/bpf" {
		return fmt.Errorf("refusing to clean unsafe pin root %q", cleanRoot)
	}
	for _, links := range m.links {
		closeLinks(links, true)
	}
	m.links = map[string][]link.Link{}
	for _, program := range []*ebpf.Program{m.objects.Connect4, m.objects.Sendmsg4, m.objects.EgressFilter} {
		if err := program.Unpin(); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	for _, object := range []*ebpf.Map{m.objects.CidrsA, m.objects.CidrsB, m.objects.RulesA, m.objects.RulesB, m.objects.ActiveConfig, m.objects.Counters, m.objects.Events} {
		if err := object.Unpin(); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return os.RemoveAll(cleanRoot)
}
