# AIOS Bible â€” Domains
## Linux â€” 003: Networking

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Domains |
| Document ID | AIOS-BBL-007-LNX-003 |
| Source Laws | Law 4 â€” Law of Evidence, Law 7 â€” Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Enable AIOS to declaratively manage Linux networking â€” interfaces, firewalls, DNS, routing, VPN, and link aggregation â€” ensuring connectivity is verifiable, atomic, and auditable.

## Architecture

Networking is modeled as a layered stack. At the physical/link layer, interfaces are configured with IP addressing and bonding. At the network layer, routing tables and policy rules are managed. At the transport/application layer, firewall rules and DNS resolution apply. Each mutation is wrapped in a transaction: changes are staged, connectivity verified, and rolled back on failure. The NetworkManager agent reconciles desired network state against live state.

### Architecture Flow

```text
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚                     NetworkManager Agent                         â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”        â”‚
â”‚  â”‚ Interfaceâ”‚  â”‚ Firewall â”‚  â”‚ Route    â”‚  â”‚ DNS      â”‚        â”‚
â”‚  â”‚ Handler  â”‚  â”‚ Handler  â”‚  â”‚ Handler  â”‚  â”‚ Handler  â”‚        â”‚
â”‚  â””â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”˜        â”‚
â”‚        â”‚             â”‚             â”‚             â”‚              â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â–¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–¼â”€â”€â”€â”€â”€â”       â”‚
â”‚  â”‚            Transaction Manager                       â”‚       â”‚
â”‚  â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  â”‚       â”‚
â”‚  â”‚  â”‚ Stage      â”‚  â”‚ Verify     â”‚  â”‚ Rollback      â”‚  â”‚       â”‚
â”‚  â”‚  â”‚ Changes    â”‚  â”‚ Connect.   â”‚  â”‚ on Fail       â”‚  â”‚       â”‚
â”‚  â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜  â”‚       â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜       â”‚
â”‚                          â”‚                                      â”‚
â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”       â”‚
â”‚  â”‚              Live Network State                       â”‚       â”‚
â”‚  â”‚  ip link   nftables   /etc/resolv.conf   route -n   â”‚       â”‚
â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜       â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
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

- **configure_interface(iface)** â€” applies IP addressing, MTU, bonding, and link state
- **add_firewall_rule(rule)** â€” inserts rule into nftables/iptables chain at priority
- **remove_firewall_rule(ruleId)** â€” deletes rule by ID
- **set_dns(entry)** â€” configures DNS resolution for hostname or search domain
- **add_route(route)** â€” adds route to routing table with metric
- **remove_route(destination)** â€” removes route from routing table
- **setup_vpn(config)** â€” establishes VPN tunnel with key material
- **verify_connectivity(targets)** â€” pings or probes endpoints after change

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

| Event Type | Produced When | Fields |
|-----------|---------------|--------|
| Linux.InterfaceConfigured | InterfaceHandler brings an interface up or down | ifaceName, ipAddresses, state, mtu, macAddress |
| Linux.InterfaceFailed | InterfaceHandler reports a configuration failure | ifaceName, error, configState, attemptedParams |
| Linux.FirewallRuleChanged | FirewallHandler adds or removes a rule | ruleId, chain, action, protocol, source, destination |
| Linux.DNSUpdated | DnsHandler changes DNS resolution configuration | hostname, resolver, entries, ttl, updatedBy |
| Linux.RouteChanged | RouteHandler adds or removes a route | destination, gateway, metric, device, table |
| Linux.VpnConnected | VpnHandler establishes a VPN tunnel | vpnName, endpoint, protocol, encryption, localIP |
| Linux.VpnDisconnected | VpnHandler tears down a VPN tunnel | vpnName, endpoint, reason, trafficStats, duration |
| Linux.ConnectivityVerified | ProbeHandler runs a connectivity probe | target, reachable, latency, packetLoss, probeId |

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

## Design DNA (table with Rule, Assessment â€” include R1,R2,R3,R4,R5,R6,R9,R10,R13,R14,R15)

| Rule | Assessment |
|------|------------|
| R1 â€” Composition over Inheritance | Network stack layers compose; interfaces contain slaves and bond options |
| R2 â€” Explicit over Implicit | Every IP, route, and rule is explicitly declared; no DHCP assumptions |
| R3 â€” Immutable Artifacts | Firewall rule sets are immutable once applied; changes create new revision |
| R4 â€” Stateless Workers | NetworkManager agent is stateless; desired state lives in manifests |
| R5 â€” Idempotency | All network operations are idempotent; same config applied twice is no-op |
| R6 â€” Observability | Every network change emits events; connectivity probes provide live status |
| R9 â€” Fail Closed | Connectivity failure triggers rollback; network stays at last known good state |
| R10 â€” Least Privilege | Firewall and route changes require elevated capability grants |
| R13 â€” Graceful Degradation | If DNS resolver fails, cached entries serve until fallback activated |
| R14 â€” Data Immutability | Network config history is append-only; rollbacks restore prior immutable snapshot |
| R15 â€” Explicit Errors | Every failure includes typed error code and recovery action |

## Related Documents (table)

| Document | Relationship |
|----------|-------------|
| Bible/07-Domains/Linux/000-Overview.md | Parent overview |
| Bible/07-Domains/Linux/002-System-Admin.md | System administration sibling |
| Physics/000-Laws.md | Audit trail for network changes |
| Physics/000-Laws.md | Capability scoping for network ops |
| Physics/005-Events.md | Event schema lineage |
| Physics/007-Capabilities.md | Capability model |
| Physics/010-Execution.md | Execution lifecycle |

## Cross-Cutting Concerns

### Security

Linux operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Linux emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Linux instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Linux declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

