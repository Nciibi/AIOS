# AIOS Bible â€” Domains
## Security â€” 001: Network Scanning

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Domains |
| Document ID | AIOS-BBL-007-SEC-001 |
| Source Laws | Law 4 â€” Law of Evidence, Law 7 â€” Law of Capability Bounds, Law 8 â€” Law of Verification-First |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/008-Security.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

Network Scanning provides the scanning engine for AIOS security operations â€” port scanning, service discovery, OS fingerprinting, banner grabbing, and vulnerability matching. It is the primary reconnaissance capability within the Security domain, enabling SecurityWorkers to map target surfaces and identify potential entry points before deeper analysis.

The engine operates under strict authorization controls (Law 7). Every scan target must be explicitly authorized by the Security Council or a delegated authority before any packet is sent. Unauthorized targets are blocked at the engine boundary regardless of the scanning mode or intensity selected.

Stealth and safety are first-order concerns. The scanning engine enforces rate limiting, random jitter, and configurable timing templates to avoid denial of service on target systems. In authorized penetration testing contexts, it supports multiple stealth profiles (TCP SYN stealth, TCP connect, UDP, ICMP, ACK scan) with full audit logging of every probe.

## Architecture

```
 +-------------------+     +------------------+     +-------------------+
 |  Reconnaissance   | --> |  Discovery        | --> |  Fingerprinting   |
 |  Target resolution |    |  Host discovery   |    |  OS detection     |
 |  Port range calc  |     |  Port scanning    |    |  Service ident    |
 +-------------------+     +------------------+     +-------------------+
                                                          |
                                                          v
 +-------------------+     +------------------+     +-------------------+
 |  Vulnerability    | <-- |  Service Enum     | <-- |  Banner Grabbing  |
 |  CVE matching     |     |  Version detect   |     |  Banner collect   |
 |  Signature match  |     |  Protocol detect  |     |  Response parse   |
 +-------------------+     +------------------+     +-------------------+
                                                          |
                                                          v
 +-------------------+
 |  Reporting        |
 |  Result normalize |
 |  Evidence seal    |
 +-------------------+
```

The pipeline processes targets through six sequential stages. Reconnaissance resolves hostnames and calculates port ranges. Discovery identifies live hosts via ping sweeps and port probes. Fingerprinting detects the operating system. Service enumeration identifies running services and versions. Vulnerability matching compares service fingerprints against the CVE database. Reporting normalizes results and seals the evidence chain.

## Data Model

```typescript
interface NetworkScan {
  scanId: string;
  targets: ScanTarget[];
  mode: ScanMode;
  stealthProfile: StealthProfile;
  rateLimit: RateLimitConfig;
  status: ScanStatus;
  startedAt: number;
  completedAt?: number;
  results: PortResult[];
  vulnerabilities: VulnerabilityMatch[];
  evidenceChain: EvidenceLink[];
  authorizationRef: string;
}

interface ScanTarget {
  hostname: string;
  resolvedIps: string[];
  ports: string;
  exclusionPorts: string[];
  authorized: boolean;
  scopeRef: string;
}

interface PortResult {
  port: number;
  protocol: 'tcp' | 'udp';
  state: 'open' | 'filtered' | 'closed' | 'blocked';
  service?: ServiceFingerprint;
  banner?: string;
  scanTimestamp: number;
}

interface ServiceFingerprint {
  name: string;
  version: string;
  protocol: string;
  confidence: number;
  cpe?: string;
  signatures: string[];
}

interface VulnerabilityMatch {
  findingId: string;
  port: number;
  service: ServiceFingerprint;
  cveIds: string[];
  matchConfidence: number;
  verified: boolean;
  verificationSandbox?: string;
}

type ScanMode = 'stealth' | 'connect' | 'udp' | 'ping' | 'version';
type StealthProfile = 'paranoid' | 'sneaky' | 'polite' | 'normal' | 'aggressive';
type ScanStatus = 'pending' | 'running' | 'completed' | 'halted' | 'failed';

interface RateLimitConfig {
  maxPacketsPerSecond: number;
  minDelayMs: number;
  randomJitterMs: number;
  parallelHosts: number;
}
```

## Core Concepts / Operations

| Operation | Preconditions | Postconditions |
|-----------|--------------|----------------|
| run_scan | Target authorized, scope validated, rate limit configured | Scan results produced, evidence chain sealed |
| discover_hosts | Scan targets resolved, probe type selected | Live hosts identified, unreachable targets flagged |
| fingerprint_os | Open ports identified, responses collected | OS detected with confidence score, fingerprint stored |
| enumerate_services | Ports open, banners captured | Service name, version, protocol identified |
| match_vulnerabilities | Service fingerprints complete, CVE DB available | CVE matches computed, confidence scored |
| halt_scan | Scan in running state | Scan halted, partial results preserved |

## Internal Interfaces

| Interface | Provider | Consumer | Protocol |
|-----------|----------|----------|----------|
| IScannerEngine | NetworkScanning | SecurityWorker, PenTestWorker | ACF sync |
| IHostDiscovery | NetworkScanning | IScannerEngine | Internal |
| IFingerprinter | NetworkScanning | IScannerEngine | Internal |
| IVulnMatcher | NetworkScanning | VulnerabilityAnalyzer (002) | ACF event |
| IAuthorizationCheck | SecurityCouncil | NetworkScanning | ACF query |

## Events

| SEC.EventType |    Produced When | Fields |
|-----------|--------------|--------|
| SEC.ScanStarted |    Scan pipeline begins execution | scan_id, target_count, mode, stealth_profile, authorization_ref |
| SEC.ScanCompleted |    All pipeline stages finish | scan_id, hosts_found, ports_open, duration_ms |
| SEC.VulnerabilityMatched |    CVE match found for a service | finding_id, scan_id, cve, service, confidence |
| SEC.ScanTargetBlocked |    Unauthorized or blacklisted target detected | target_ip, reason, authorization_ref, resolver_id |
| SEC.ScanProgress |    Periodic progress heartbeat | scan_id, stage, percent_complete, estimated_remaining |
| SEC.ScanHalted |    Scan interrupted by operator or boundary | scan_id, halted_by, reason, partial_results_ref |
| SEC.ScanRateLimited |    Rate limit threshold approached | scan_id, current_rate, max_rate, throttle_applied |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|----------|
| SEC-NS-001 | Target unreachable â€” no response to probes | Low | Skip host, continue scan, flag in results |
| SEC-NS-002 | Scan timeout exceeded per-target limit | Medium | Abort target, preserve partial results, continue |
| SEC-NS-003 | Rate limit exceeded â€” target defensive threshold | Medium | Back off, apply exponential delay, resume |
| SEC-NS-004 | Unauthorized target detected in scope | Critical | Halt scan immediately, escalate to Security Council |
| SEC-NS-005 | CVE database unavailable for matching | Low | Complete scan without vuln matching, flag for retry |
| SEC-NS-006 | Stealth profile violation â€” IDS/IPS detected | High | Switch to lower-profile mode, log detection event |
| SEC-NS-007 | Scan engine internal error â€” packet send failure | Medium | Retry stage up to 3 times, fail target on exhaustion |
| SEC-NS-008 | Banner buffer overflow â€” malformed response | Low | Truncate banner, continue enumeration |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| SEC-NS-I-001 | No scan executed without valid authorization | Authorization check at pipeline entry, immutable audit |
| SEC-NS-I-002 | Rate limiting must prevent DoS on target | Hard cap on packets-per-second per target, runtime enforcement |
| SEC-NS-I-003 | All probe results preserved in evidence chain | Immutable append-only log per scan, cryptographic seal |
| SEC-NS-I-004 | Blocked targets are never probed | Pre-filter at resolution stage, zero exceptions |
| SEC-NS-I-005 | Original raw responses preserved for independent verification | Raw response store, separate from parsed results |
| SEC-NS-I-006 | Vulnerability matches require sandbox verification before report | SEC-001 match creates provisional finding, SEC-002 verification |


## Cross-Cutting Concerns

### Security

Security operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Security emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Security instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Security declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 - Modulsingularity | Each pipeline stage (discovery, fingerprinting, vuln matching) is a separate module with well-defined interfaces |
| R2 - Dependency Order | Scan config, targets, results, and evidence sealed as an atomic scan capsule |
| R3 - DRY | Identical targets and config produce identical scan results â€” deterministic fingerprinting |
| R4 - Builder Pattern | Scan result is built incrementally through pipeline stages â€” immutable stage outputs |
| R5 - Liskov Substitution | Scan authorization is a manual gate â€” no automated scan without explicit approval |
| R6 - DI over Singletons | Halted scans preserve partial results â€” no unreclaimed scan resources |
| R9 - Deterministic | Same CPE fingerprint and CVE DB version yields identical match set |
| R10 - Simpler Over Complex | Every probe, match, and block produces an event â€” full reconstruction from event log |
| R13 - Design for Failure | Engine fails closed â€” unauthorized targets never probed even on internal error |
| R14 - Paved Path | Scan artifacts retained for audit window, then garbage collected |
| R15 - Open/Closed | Every scan links to authorization chain â€” verified at each stage boundary |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/07-Domains/Security/000-Overview.md | Overview â€” Network scanning is a core vulnerability assessment capability |
| Bible/07-Domains/Security/002-Vulnerability-Analysis.md | Downstream â€” Vulnerability matches feed into analysis engine |
| Bible/07-Domains/Security/003-Forensics.md | Evidence â€” Scan evidence feeds forensic timeline reconstruction |
| Bible/04-Execution/Security/000-Overview.md | Runtime â€” Scan engine execution authorization |
| Bible/04-Execution/Security/Pentest/000-Overview.md | Pentest â€” Network scanning is primary pentest reconnaissance tool |
| Bible/04-Execution/Security/Sandbox/000-Isolation.md | Verification â€” Vulnerability matches verified in sandbox |
| Bible/04-Execution/Security/AZS/000-RBAC.md | Authorization â€” RBAC policies govern scan target authorization |
| Bible/04-Execution/Security/Audit/000-EAS.md | Audit â€” Evidence Audit Service records all scan operations |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001â€“010 â€” Core principles governing security operations |
