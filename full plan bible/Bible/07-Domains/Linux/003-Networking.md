# AIOS Bible — Domains
## Linux — 003: Networking

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Domains |
| Document ID | AIOS-BBL-007-LNX-003 |
| Source Laws | Law 4 — Law of Evidence, Law 7 — Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Enable AIOS to declaratively manage Linux networking — interfaces, firewalls, DNS, routing, VPN, and link aggregation — ensuring connectivity is verifiable, atomic, and auditable.

## Architecture

Networking is modeled as a layered stack. At the physical/link layer, interfaces are configured with IP addressing and bonding. At the network layer, routing tables and policy rules are managed. At the transport/application layer, firewall rules and DNS resolution apply. Each mutation is wrapped in a transaction: changes are staged, connectivity verified, and rolled back on failure. The NetworkManager agent reconciles desired network state against live state.

### Architecture Flow

```text
┌─────────────────────────────────────────────────────────────────┐
│                     NetworkManager Agent                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │ Interface│  │ Firewall │  │ Route    │  │ DNS      │        │
│  │ Handler  │  │ Handler  │  │ Handler  │  │ Handler  │        │
│  └─────┬────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘        │
│        │             │             │             │              │
│  ┌─────▼─────────────▼─────────────▼─────────────▼─────┐       │
│  │            Transaction Manager                       │       │
│  │  ┌────────────┐  ┌────────────┐  ┌───────────────┐  │       │
│  │  │ Stage      │  │ Verify     │  │ Rollback      │  │       │
│  │  │ Changes    │  │ Connect.   │  │ on Fail       │  │       │
│  │  └────────────┘  └────────────┘  └───────────────┘  │       │
│  └───────────────────────┬──────────────────────────────┘       │
│                          │                                      │
│  ┌───────────────────────▼──────────────────────────────┐       │
│  │              Live Network State                       │       │
│  │  ip link   nftables   /etc/resolv.conf   route -n   │       │
│  └──────────────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

## Data Model (TypeScript interfaces)

```typescript
interface NetworkInterface {
  name: string;
  type: 'ethernet' | 'wireless' | 'bond' | 'vlan' | 'bridge';
  macAddress?: string;
  ipAddresses: string[];
  netmask: string;
  gateway?: string;
  mtu?: number;
  bondOptions?: Record<string, string>;
  vlanId?: number;
  slaves?: string[];
  state: 'up' | 'down';
}

interface FirewallRule {
  id: string;
  chain: 'INPUT' | 'OUTPUT' | 'FORWARD';
  protocol: 'tcp' | 'udp' | 'icmp' | 'any';
  source: string;
  destination: string;
  port?: number;
  action: 'ACCEPT' | 'DROP' | 'REJECT';
  priority: number;
  state: 'active' | 'disabled';
}

interface DNSEntry {
  hostname: string;
  addresses: string[];
  type: 'A' | 'AAAA' | 'CNAME' | 'MX';
  ttl: number;
  resolver: 'systemd-resolved' | 'resolvconf' | 'dnsmasq';
}

interface RouteConfig {
  destination: string;
  gateway: string;
  interface: string;
  metric: number;
  table?: string;
  type: 'unicast' | 'blackhole' | 'unreachable';
}

interface VpnConfig {
  name: string;
  type: 'wireguard' | 'openvpn' | 'ipsec';
  endpoint: string;
  localAddress: string;
  remoteNetwork: string;
  allowedIPs: string[];
  privateKeyRef: string;
  peerPublicKey: string;
  persistentKeepalive: number;
}

interface BondConfig {
  name: string;
  mode: 'balance-rr' | 'active-backup' | 'balance-xor' | 'broadcast' | '802.3ad' | 'balance-tlb' | 'balance-alb';
  slaves: string[];
  miimon: number;
  updelay: number;
  downdelay: number;
  lacpRate?: 'slow' | 'fast';
  state: 'up' | 'down';
}

interface TrafficControlRule {
  id: string;
  interface: string;
  direction: 'ingress' | 'egress';
  handle: string;
  parent: string;
  discipline: 'htb' | 'tbf' | 'fq_codel' | 'pfifo_fast';
  rate?: string;
  ceil?: string;
  burst?: number;
  state: 'active' | 'disabled';
}

interface DhcpRelayConfig {
  name: string;
  interface: string;
  serverAddress: string;
  options: Record<string, string>;
  state: 'running' | 'stopped';
}
```

## Core Concepts / Operations

- **configure_interface(iface)** — applies IP addressing, MTU, bonding, and link state
- **add_firewall_rule(rule)** — inserts rule into nftables/iptables chain at priority
- **remove_firewall_rule(ruleId)** — deletes rule by ID
- **set_dns(entry)** — configures DNS resolution for hostname or search domain
- **add_route(route)** — adds route to routing table with metric
- **remove_route(destination)** — removes route from routing table
- **setup_vpn(config)** — establishes VPN tunnel with key material
- **verify_connectivity(targets)** — pings or probes endpoints after change

### Operations Table

| Operation | Description | Preconditions | Postconditions |
|-----------|-------------|---------------|----------------|
| configure_interface | Applies IP addressing, MTU, bonding, and link state | Interface exists; kernel driver loaded | Interface configured with IP, MTU, state; link verified |
| add_firewall_rule | Inserts rule into nftables/iptables chain at priority | nftables/iptables available; chain exists | Rule inserted; nftables config persisted |
| remove_firewall_rule | Deletes rule by ID | Rule ID exists in active firewall set | Rule removed; firewall state updated |
| set_dns | Configures DNS resolution for hostname or search domain | Resolver service running | DNS entry created/updated; resolver config reloaded |
| add_route | Adds route to routing table with metric | Destination network valid; gateway reachable | Route added; routing table updated; no overlap detected |
| remove_route | Removes route from routing table | Route exists in routing table | Route removed; traffic redirected to remaining routes |
| setup_vpn | Establishes VPN tunnel with key material | VPN type supported; key material accessible; endpoint reachable | VPN tunnel established; allowedIPs routed through tunnel |
| verify_connectivity | Pings or probes endpoints after change | Target endpoints specified; ICMP/probe protocol allowed | Connectivity status reported; logs written to audit trail |
| configure_bond | Creates or modifies bond interface with slaves | Minimum 2 slaves available; bonding driver loaded | Bond interface created; slaves enslaved; link aggregation active |
| configure_vlan | Creates or removes VLAN interface | Parent interface exists; 8021q module loaded | VLAN interface created with tagged VID; traffic isolated |
| set_traffic_control | Applies traffic shaping or QoS rule | tc tool available; interface exists | QoS discipline attached; rate/ceil limits enforced |
| configure_dhcp_relay | Sets up DHCP relay agent on interface | DHCP relay package installed; server reachable | DHCP relay running; BOOTP requests forwarded to server |

## Internal Interfaces (table)

| Interface | Provider | Consumer | Purpose |
|-----------|----------|----------|---------|
| IInterfaceManager | InterfaceHandler | NetworkManager | Configure interface state |
| IFirewallManager | FirewallHandler | NetworkManager | Add/remove firewall rules |
| IDnsManager | DnsHandler | NetworkManager | Manage DNS entries |
| IRouteManager | RouteHandler | NetworkManager | Manage routing table |
| IVpnManager | VpnHandler | NetworkManager | Establish/tear down VPN |
| IConnectivityProbe | ProbeHandler | NetworkManager | Verify network connectivity |
| IBondManager | BondHandler | NetworkManager | Manage bond interface configuration |
| ITrafficControlManager | TrafficControlHandler | NetworkManager | Apply traffic shaping and QoS rules |
| IDhcpRelayManager | DhcpRelayHandler | NetworkManager | Configure DHCP relay agents |

## Events (table)

| Event | Emitter | Payload | Meaning |
|-------|---------|---------|---------|
| Linux.InterfaceConfigured | InterfaceHandler | { ifaceName, ipAddresses, state } | Interface brought up or down |
| Linux.InterfaceFailed | InterfaceHandler | { ifaceName, error } | Interface configuration failed |
| Linux.FirewallRuleChanged | FirewallHandler | { ruleId, chain, action } | Firewall rule added or removed |
| Linux.DNSUpdated | DnsHandler | { hostname, resolver, entries } | DNS resolution configuration changed |
| Linux.RouteChanged | RouteHandler | { destination, gateway, metric } | Route added or removed |
| Linux.VpnConnected | VpnHandler | { vpnName, endpoint } | VPN tunnel established |
| Linux.VpnDisconnected | VpnHandler | { vpnName, reason } | VPN tunnel torn down |
| Linux.ConnectivityVerified | ProbeHandler | { target, reachable, latency } | Connectivity probe result |

## Error Cases (table with Code, Condition, Severity, Recovery)

| Code | Condition | Severity | Recovery |
|------|-----------|----------|----------|
| NET-001 | Network interface not found | Error | Verify interface name, list available interfaces |
| NET-002 | Firewall rule conflicts with existing rule | Warning | Log conflict, suggest priority adjustment |
| NET-003 | DNS resolution failure after config change | Error | Rollback DNS config, verify resolver health |
| NET-004 | Route overlap with existing route | Warning | Reject new route, show conflicting route |
| NET-005 | VPN endpoint unreachable | Error | Retry with backoff, verify endpoint address/firewall |
| NET-006 | Interface bonding requires minimum 2 slaves | Error | Block bond creation until sufficient slaves added |
| NET-007 | Connectivity verification failed after change | Critical | Roll back network change, restore previous state |

## Invariants (table with ID, Rule, Enforcement)

| ID | Rule | Enforcement |
|----|------|-------------|
| NET-INV-01 | Every network change includes connectivity verification | NetworkManager runs probe after every mutation |
| NET-INV-02 | Firewall rules are applied atomically in a single transaction | Rules are batched into atomic nftables transaction |
| NET-INV-03 | No duplicate routes to the same destination | RouteHandler checks for overlap before insertion |
| NET-INV-04 | DNS resolver is reachable before config is committed | DnsHandler validates resolver response before write |
| NET-INV-05 | Interface IP addresses do not conflict within subnet | InterfaceHandler validates IP uniqueness on subnet |
| NET-INV-06 | VPN private key references are never logged or exposed | VpnHandler stores keys in secret store, uses reference |

## Design DNA (table with Rule, Assessment — include R1,R2,R3,R4,R5,R6,R9,R10,R13,R14,R15)

| Rule | Assessment |
|------|------------|
| R1 — Composition over Inheritance | Network stack layers compose; interfaces contain slaves and bond options |
| R2 — Explicit over Implicit | Every IP, route, and rule is explicitly declared; no DHCP assumptions |
| R3 — Immutable Artifacts | Firewall rule sets are immutable once applied; changes create new revision |
| R4 — Stateless Workers | NetworkManager agent is stateless; desired state lives in manifests |
| R5 — Idempotency | All network operations are idempotent; same config applied twice is no-op |
| R6 — Observability | Every network change emits events; connectivity probes provide live status |
| R9 — Fail Closed | Connectivity failure triggers rollback; network stays at last known good state |
| R10 — Least Privilege | Firewall and route changes require elevated capability grants |
| R13 — Graceful Degradation | If DNS resolver fails, cached entries serve until fallback activated |
| R14 — Data Immutability | Network config history is append-only; rollbacks restore prior immutable snapshot |
| R15 — Explicit Errors | Every failure includes typed error code and recovery action |

## Related Documents (table)

| Document | Relationship |
|----------|-------------|
| Bible/07-Domains/Linux/000-Overview.md | Parent overview |
| Bible/07-Domains/Linux/002-System-Admin.md | System administration sibling |
| Bible/07-Laws/Law-004-Evidence.md | Audit trail for network changes |
| Bible/07-Laws/Law-007-Capability-Bounds.md | Capability scoping for network ops |
| Bible/Physics/005-Events.md | Event schema lineage |
| Bible/Physics/007-Capabilities.md | Capability model |
| Bible/Physics/010-Execution.md | Execution lifecycle |
