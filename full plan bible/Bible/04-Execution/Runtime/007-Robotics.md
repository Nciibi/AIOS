# AIOS Bible — Execution
## 007 — Robotics Execution Provider

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0 |
| Category | Bible — Execution/Runtime |
| Document ID | AIOS-BBL-004-RTM-007 |
| Source Laws | Law 2 — Law of Non-Execution, Law 7 — Law of Capability Bounds |
| Source Physics | Physics/010-Execution.md, Physics/007-Capabilities.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Robotics Provider executes physical robot control actions — motion planning, actuator commands, sensor data acquisition, and state management — through hardware abstraction layer (HAL) interfaces. It bridges the AIOS digital execution environment with physical robotic systems. Every action is bounded by safety constraints, verified by the execution token, and recorded for forensic analysis.

## Capability Declaration

| Property | Value |
|----------|-------|
| provider_id | `aios.provider.robotics` |
| action_types | `robot.motion`, `robot.gripper`, `robot.sensor`, `robot.state`, `robot.program`, `robot.pose` |
| max_parallelism | 4 concurrent executions (per robot) |
| default_timeout_ms | 120000 (2 minutes) |
| supported_autonomy_levels | L0, L1 (L2+ requires Human Override) |

## Action Types

| Action Type | Description | Parameters |
|-------------|-------------|------------|
| `robot.motion` | Execute a motion plan (joint or Cartesian) | target_pose, motion_type (joint/cartesian/linear), speed, acceleration, blending |
| `robot.gripper` | Control gripper or end effector | action (open/close/grip/release), force, width, timeout |
| `robot.sensor` | Read sensor data from robot or peripheral | sensor_id, data_type (force/torque/vision/proximity/temperature), sample_count |
| `robot.state` | Query or set robot state | state_variable (power/mode/safety_status/error_state), value |
| `robot.program` | Upload and execute a robot program | program_id, program_content (URScript/Python/RAPID), variables |
| `robot.pose` | Get or set the robot's current pose | reference_frame (base/tool/user), pose (x, y, z, rx, ry, rz) |

## Safety Architecture

The Robotics Provider implements a three-layer safety model:

1. **Token Bounds**: Every action must be within the capability bounds declared in the execution token — max speed, max force, allowed workspaces, and prohibited poses
2. **Provider Safeguards**: The provider enforces hard limits at the HAL level that cannot be overridden by the execution token — joint limits, singularities, collision boundaries, and emergency stop state
3. **Hardware Safety**: Physical safety systems (e-stop, light curtains, torque limits) operate independently of software enforcement

If any safety bound is exceeded, the provider immediately stops all motion, returns a SafetyViolation error, and sets the robot state to SafetyHalt. Recovery requires a new execution token with explicit safety reset authorization.

## Hardware Abstraction Layer

The provider communicates with robot hardware through a HAL adapter interface. Supported adapters:

| Adapter | Protocol | Supported Robots |
|---------|----------|------------------|
| Universal Robots | Dashboard Server + Primary Interface | UR3e, UR5e, UR10e, UR20 |
| ROS 2 | actionlib + topics (via rosbridge) | Any ROS 2-compatible robot |
| Modbus TCP | Modbus holding registers | PLC-controlled custom robots |
| Simulated | In-memory kinematics | Digital twin for testing and dry-run |

The Simulated adapter runs a kinematic model of the robot and validates all motion requests against the same safety checks as a physical robot. No physical movement occurs in Simulated mode.

## Motion Execution Flow

1. Provider receives a `robot.motion` action with a verified execution token
2. Provider validates the target pose against the capability bounds (workspace envelope, speed limits, force limits)
3. Provider checks inverse kinematics (is the target pose reachable?)
4. Provider verifies no singularity condition exists on the planned path
5. Provider validates the motion against active safety zones (no-go zones, speed limit zones)
6. Provider sends motion command to the robot through the HAL adapter
7. Provider monitors execution in real-time (joint positions, speeds, torques, safety status)
8. On completion, provider returns final pose, path deviation metrics, and execution duration
9. If a safety violation occurs at any step, provider executes an immediate stop

## Error Handling

| Error Code | Condition | Action |
|------------|-----------|--------|
| RBT-0001 | Target pose outside workspace envelope | Deny; return workspace bounds |
| RBT-1001 | Singularity detected on planned path | Deny; suggest alternative pose |
| RBT-2001 | Safety zone violation | Immediate stop; set SafetyHalt state; return violation details |
| RBT-3001 | Joint limit exceeded during motion | Immediate stop; return joint positions at violation |
| RBT-4001 | Robot communication timeout | Execute safety stop; mark robot as Unreachable |
| RBT-5001 | Gripper force exceeds limit | Stop gripper; return actual force at stop |
| RBT-6001 | Emergency stop activated | Return E-stop event; provider enters E-stop state |
| RBT-7001 | Sensor read failure | Return degraded sensor status; continue with available sensors |

## Events

| Event Type | Fields |
|------------|--------|
| `Provider.Robotics.MotionPlanned` | execution_id, target_pose, plan_length, estimated_duration |
| `Provider.Robotics.MotionStarted` | execution_id, start_pose, speed, acceleration |
| `Provider.Robotics.MotionStep` | execution_id, sequence, joint_positions, speed_pct, torque_readings |
| `Provider.Robotics.MotionCompleted` | execution_id, end_pose, path_deviation, duration_ms |
| `Provider.Robotics.MotionFailed` | execution_id, error_code, error_message, halted_pose |
| `Provider.Robotics.SafetyViolation` | execution_id, violation_type, bound_value, actual_value, timestamp |
| `Provider.Robotics.GripperActuated` | execution_id, action, force, width, object_detected |
| `Provider.Robotics.SensorDataReceived` | execution_id, sensor_id, data_type, reading_count |
| `Provider.Robotics.ProgramExecuted` | execution_id, program_id, exit_code, output_lines |

## Cross-Cutting Concerns

### Security

The provider validates every action against the robot's declared safety bounds before sending any command to hardware. The provider's HAL layer enforces a separate set of hard limits that cannot be modified by the execution token or provider configuration. Emergency stop state overrides all software control. All actions are logged with full telemetry for forensic analysis.

### Evidence

Every motion command produces a MotionPlanned → MotionStarted → MotionStep* → MotionCompleted/Failed Event chain. Safety violations produce immediate SafetyViolation Events with full telemetry context. Sensor readings are recorded as snapshot Events.

### Lifecycle

The provider manages the robot connection lifecycle. On `initialize()`, it connects to the robot controller, reads the robot's current state, and validates that safety systems are operational. On `shutdown()`, it brings the robot to a safe stop and disconnects. Health checks verify robot connectivity, safety system status, and HAL adapter readiness.

### Capability Bounds

The provider enforces: workspace envelope (Cartesian bounds), joint limits (position, speed, acceleration, torque), max TCP speed, max TCP force, allowed motion types, safety zone definitions, gripper force limits, sensor sampling rate limits, and autonomy level restrictions (L2+ requires Human Override).

### Communication

The provider communicates with robot controllers through the HAL adapter's protocol (TCP/UDP, Modbus TCP, ROS 2 middleware). Provider-to-Runtime communication uses the SDK interface. The provider does not expose any network-accessible endpoints.

### Design DNA

| Rule | Assessment |
|------|------------|
| R1 | Provider handles only robotics execution — no model inference, no financial operations |
| R5 | HAL adapters are interchangeable; Simulated adapter enables safe testing |
| R10 | Motion execution is linear: validate → plan → execute → monitor → return |
| R12 | Every safety and hardware error has a unique RBT-NNNN code with telemetry context |
| R13 | Safety violations trigger immediate stop (fail-closed); all safety bounds are hard limits |
| R14 | Paved path: validate bounds → IK solve → safety check → execute → monitor → record |
| R15 | New robot types implement the HAL adapter interface without modifying the provider |

## Related Documents

| Document | Relationship |
|----------|-------------|
| Bible/04-Execution/Runtime/000-Overview.md | Runtime Engine architecture |
| Bible/04-Execution/Runtime/001-SDK.md | Provider SDK used to build this provider |
| Physics/010-Execution.md | Execution invariants for physical system control |
| Physics/007-Capabilities.md | Capability bounds for workspace, speed, and force limits |
