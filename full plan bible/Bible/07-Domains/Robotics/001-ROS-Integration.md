# AIOS Bible â€” Domains
## Robotics â€” 001: ROS/ROS2 Integration

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Domains |
| Document ID | AIOS-BBL-007-ROB-001 |
| Source Laws | Law 4 â€” Law of Evidence, Law 7 â€” Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The ROS/ROS2 Integration subsystem enables AIOS to generate, configure, build, and deploy ROS and ROS2 packages, nodes, topics, services, actions, launch files, and DDS configurations. It provides a deterministic code generation pipeline that produces standard-compliant ROS artifacts from high-level specifications, eliminating manual ROS boilerplate while ensuring type safety and DDS QoS consistency across the entire robot software stack.

## Architecture

```
Requirements â†’ Package Scaffold â†’ Node Templates â†’ Topic/Service Config â†’ Build â†’ Deploy
```

| Stage | Input | Output | Worker |
|-------|-------|--------|--------|
| Requirements | Robot model, interface spec, capability list | Package manifest (package.xml, CMakeLists.txt) | RoboticsWorker |
| Package Scaffold | Package manifest | Directory structure, build system files | RoboticsWorker |
| Node Templates | Node specification (publishers, subscribers, services) | C++/Python node source code | RoboticsWorker |
| Topic/Service Config | Topic types, service types, QoS profiles | Interface definitions (.msg, .srv, .action) | RoboticsWorker |
| Build | Source code, interface definitions | Compiled ROS packages, binaries | SimulationWorker |
| Deploy | Built packages, launch files | Running ROS nodes on target | RoboticsWorker |

## Data Model (TypeScript)

```typescript
interface ROSPackage {
  name: string;
  version: string;
  description: string;
  maintainer: string;
  buildType: "ament_cmake" | "ament_python" | "cmake";
  dependencies: string[];
  nodes: ROSNode[];
  interfaces: ROSInterface[];
  launchFiles: LaunchFile[];
  ddsConfig: DDSConfig;
}

interface ROSNode {
  name: string;
  namespace: string;
  language: "cpp" | "python";
  publishers: TopicDefinition[];
  subscribers: TopicDefinition[];
  serviceServers: ServiceDefinition[];
  serviceClients: ServiceDefinition[];
  actionServers: ActionDefinition[];
  actionClients: ActionDefinition[];
  parameters: ROSParameter[];
  timers: TimerConfig[];
}

interface TopicDefinition {
  name: string;
  type: string;
  qosProfile: QOSProfile;
  reliability: "best_effort" | "reliable";
  durability: "volatile" | "transient_local" | "transient" | "persistent";
  depth: number;
}

interface ServiceDefinition {
  name: string;
  type: string;
  requestType: string;
  responseType: string;
}

interface ActionDefinition {
  name: string;
  type: string;
  goalType: string;
  resultType: string;
  feedbackType: string;
}

interface LaunchFile {
  name: string;
  format: "xml" | "python" | "yaml";
  nodes: LaunchNodeConfig[];
  remappings: RemappingRule[];
  arguments: LaunchArgument[];
}

interface DDSConfig {
  domainId: number;
  discoveryTimeoutMs: number;
  transport: "udp" | "shm" | "tcp";
  securityEnabled: boolean;
  securityFiles?: {
    governance: string;
    permissions: string;
    identityCa: string;
    identityCert: string;
    identityKey: string;
  };
}

interface ROSParameter {
  name: string;
  type: "bool" | "int" | "double" | "string" | "byte[]" | "bool[]" | "int[]" | "double[]" | "string[]";
  value: unknown;
  description: string;
}

interface TimerConfig {
  name: string;
  periodMs: number;
  callback: string;
}

interface LaunchNodeConfig {
  package: string;
  executable: string;
  namespace: string;
  arguments: Record<string, string>;
  remappings: RemappingRule[];
}

interface RemappingRule {
  from: string;
  to: string;
}

interface LaunchArgument {
  name: string;
  defaultValue: string;
  description: string;
}

interface QOSProfile {
  history: "keep_last" | "keep_all" | "system_default";
  depth: number;
  reliability: "best_effort" | "reliable";
  durability: "volatile" | "transient_local" | "transient" | "persistent";
  deadlineMs?: number;
  lifespanMs?: number;
  liveliness: "automatic" | "manual_by_topic" | "system_default";
  livelinessLeaseDurationMs: number;
}

interface ROSInterface {
  type: "msg" | "srv" | "action";
  name: string;
  fields: ROSInterfaceField[];
}

interface ROSInterfaceField {
  name: string;
  type: string;
  defaultValue?: string;
}
```

## Core Concepts / Operations

| Operation | Input | Output | Description |
|-----------|-------|--------|-------------|
| create_package | PackageSpec | ROSPackage | Scaffolds a ROS/ROS2 package with manifest, build files, and directory structure |
| generate_node | ROSPackage, NodeSpec | ROSNode | Generates C++ or Python node source code with configured publishers, subscribers, services, and actions |
| configure_topic | ROSNode, TopicDefinition | TopicDefinition | Adds or updates a topic publisher or subscriber on an existing node |
| define_service | ROSNode, ServiceDefinition | ServiceDefinition | Adds a ROS service server or client to a node |
| create_action | ROSNode, ActionDefinition | ActionDefinition | Adds a ROS action server or client to a node |
| define_interface | ROSPackage, ROSInterface | ROSInterface | Creates a .msg, .srv, or .action interface definition file |
| generate_launch_file | LaunchSpec | LaunchFile | Generates a launch file (XML, Python, or YAML format) for a set of nodes |
| configure_dds | ROSPackage, DDSConfig | DDSConfig | Applies DDS configuration including domain ID, transport, and security settings |
| build_package | ROSPackage | BuildResult | Builds the ROS package and returns build artifacts |
| validate_package | ROSPackage | ValidationResult | Validates package structure, interface types, and dependency completeness |

## Internal Interfaces

| Interface | Provider | Consumer | Description |
|-----------|----------|----------|-------------|
| IPackageGenerator | ROS Integration | RoboticsWorker | Generates ROS package scaffolds from specifications |
| INodeGenerator | ROS Integration | RoboticsWorker | Generates ROS node source code from node specifications |
| IInterfaceRegistry | ROS Integration | RoboticsWorker | Manages .msg, .srv, .action definition lifecycle |
| ILaunchGenerator | ROS Integration | RoboticsWorker | Generates launch files from launch specifications |
| IDDSConfigurator | ROS Integration | RoboticsWorker | Applies DDS configuration to ROS packages |

## Events

| ROB.EventType | Produced When | Fields |
|-----------|--------------|--------|
| Robotics.ROSPackageCreated | ROS package scaffold is generated | package_id, package_name, version, build_type, node_count, interface_count |
| Robotics.ROSNodeGenerated | ROS node source code is generated | node_id, node_name, language, package_name, publisher_count, subscriber_count, service_count, action_count |
| Robotics.ROSInterfaceDefined | ROS msg/srv/action interface is created | interface_id, interface_name, interface_type, field_count, package_name |
| Robotics.ROSGraphUpdated | ROS topic/service graph is modified | graph_id, node_name, added_topics, removed_topics, added_services, removed_services |
| Robotics.ROSLaunchDeployed | Launch file is deployed and nodes start | launch_id, launch_file, node_count, target_platform, deployment_time_ms |
| Robotics.ROSSecurityConfigured | DDS security configuration is applied | config_id, domain_id, transport, security_enabled, package_name |
| Robotics.ROSBuildCompleted | ROS package build finishes | build_id, package_name, success, error_count, warning_count, build_time_ms |
| Robotics.ROSPackageValidated | ROS package validation completes | validation_id, package_name, is_valid, errors, warnings |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|----------|
| ROB-ROS-001 | Node naming conflict â€” two nodes with the same name in the same namespace | Error | Reject generation. Prompt user to rename node or change namespace. |
| ROB-ROS-002 | Topic type mismatch â€” publisher and subscriber on same topic have different message types | Error | Detect during validation. Flag mismatch with topic name and conflicting types. Block build until resolved. |
| ROB-ROS-003 | DDS discovery failure â€” nodes cannot discover each other across the DDS network | Warning | Retry discovery with increased timeout. Fall back to static endpoint discovery. Log topology for debugging. |
| ROB-ROS-004 | Package build failure â€” compilation or dependency resolution error | Error | Capture build logs. Identify root cause (missing dependency, syntax error, type mismatch). Report actionable error to developer. |
| ROB-ROS-005 | Interface type undefined â€” referenced .msg/.srv/.action file not found | Error | Fail validation. List missing interface files. Suggest package dependencies required to resolve. |
| ROB-ROS-006 | QoS profile incompatibility â€” publisher/subscriber QoS settings are incompatible | Warning | Detect during graph validation. Report incompatible QoS pairs. Suggest compatible QoS profiles. |
| ROB-ROS-007 | Launch file syntax error â€” malformed XML/Python/YAML launch configuration | Error | Parse and validate launch file during generation. Report exact line and syntax issue. |
| ROB-ROS-008 | DDS security misconfiguration â€” missing or invalid security certificate files | Critical | Halt deployment. Report missing or expired certificates. Require Security Council re-authorization. |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| ROB-ROS-I-001 | Deterministic node generation â€” identical NodeSpec input must produce identical source code output | Hash comparison on generated source files. Non-determinism triggers DTS incident. |
| ROB-ROS-I-002 | Topic type consistency â€” a topic name must map to exactly one message type across all nodes in the same ROS graph | Graph validation before build. Type mismatch blocks package generation. |
| ROB-ROS-I-003 | DDS QoS compliance â€” generated QoS profiles must be compatible within each publisher-subscriber pair | QoS compatibility matrix check during validation. Incompatible pairs reported as errors. |
| ROB-ROS-I-004 | Interface uniqueness â€” no two .msg/.srv/.action definitions within a package may share the same name and type | Package validation enforces unique interface names. Duplicates rejected during scaffold. |
| ROB-ROS-I-005 | Launch file completeness â€” every node referenced in a launch file must have a corresponding generated node definition | Cross-reference validation between launch file and package node list. Missing nodes trigger error. |
| ROB-ROS-I-006 | Security certificate validity â€” DDS security certificates must not be expired at time of deployment | Certificate expiration check before deployment. Expired certificates block deployment and trigger renewal workflow. |

## Design DNA (R1-R6,R9,R10,R13-R15)

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Each ROS capability (package generation, node generation, interface management, launch generation, DDS config) is a separate module with a single responsibility |
| R2 (Encapsulation) | ROS package internals (source files, build artifacts) are encapsulated within the package boundary; external access only through defined interfaces |
| R3 (Orthogonality) | Package generation, node generation, interface definition, launch generation, and DDS configuration are orthogonal â€” any combination can be used independently |
| R4 (Polymorphism) | Generated nodes support both C++ and Python languages through polymorphic code generation templates |
| R5 (Liskov) | All generated ROS nodes conform to the ROSNode interface contract regardless of language or execution context |
| R6 (Interface) | ROS integration exposes narrow interfaces (IPackageGenerator, INodeGenerator) that decouple consumers from generation internals |
| R9 (Deterministic) | Same ROS specification input produces identical package output every time â€” no randomness in code generation |
| R10 (Simpler Over Complex) | Use package defaults where possible; only require explicit configuration when deviating from ROS community standards |
| R13 (Design for Failure) | Package build failures preserve full build logs and intermediate artifacts for debugging; validation catches errors before build |
| R14 (Paved Path) | Paved path: specify interfaces â†’ generate package â†’ build â†’ validate â†’ deploy. Alternative paths available for advanced use cases |
| R15 (Testability) | Each generator module has independently testable output; generated nodes can be unit tested without ROS runtime |


## Cross-Cutting Concerns

### Security

Robotics operates under Law 8 (Verification-First) and Law 7 (Capability Bounds): every operation is authorized by the Security Kernel before execution, and the component never exceeds its declared capabilities. (Physics/008-Security.md)

### Evidence

Per Law 4 (Evidence), Robotics emits an evidence record for each significant state change - what changed, by whom, on what basis, with what outcome - delivered through ACF and persisted by EVS. (Physics/005-Events.md)

### Lifecycle

Per Law 6 (Lifecycle Compliance), Robotics instances follow the canonical LMS lifecycle (Draft -> Active -> Suspended -> Archived) and are terminated deterministically; orphan states are prevented. (Physics/006-Lifecycles.md)

### Capability Bounds

Per Law 7 (Capability Bounds), Robotics declares its capabilities at creation and operates only within them; capability expansion requires reauthorization through the Security Kernel. (Physics/007-Capabilities.md)

## Related Documents

| Document | Relationship |
|---------|-------------|
| Bible/07-Domains/Robotics/000-Overview.md | Domain overview â€” ROS Integration is a core Robotics capability |
| Bible/07-Domains/Robotics/002-Sensor-Fusion.md | Sensor Fusion â€” consumes ROS topics generated by ROS Integration |
| Bible/07-Domains/Robotics/003-Motion-Planning.md | Motion Planning â€” depends on ROS topics and services for trajectory commands |
| Physics/005-Events.md | Evidence â€” all ROS generation operations produce Events |
| Physics/007-Capabilities.md | Capabilities â€” ROS node generation is a bounded capability |
| Physics/010-Execution.md | Execution â€” ROS nodes execute as Workers within the AIOS execution model |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001â€“010 â€” philosophical grounding for deterministic code generation |
