# AIOS Bible â€” Domains
## Robotics â€” 003: Motion Planning

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Domains |
| Document ID | AIOS-BBL-007-ROB-003 |
| Source Laws | Law 4 â€” Law of Evidence, Law 7 â€” Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/010-Execution.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Motion Planning subsystem enables AIOS to compute safe, collision-free, and kinematically feasible trajectories for robotic manipulators, mobile robots, drones, and autonomous vehicles. It provides inverse kinematics solvers, collision checking against static and dynamic obstacles, trajectory optimization, path smoothing, and real-time replanning capabilities. All motion plans are validated in simulation before execution on physical hardware.

## Architecture

```
Start/Goal â†’ Collision Checking â†’ Kinematics Solver â†’ Trajectory Optimization â†’ Validation â†’ Execution
```

| Stage | Input | Output | Worker |
|-------|-------|--------|--------|
| Start/Goal | Current state, target pose, constraints | Problem specification | RoboticsWorker |
| Collision Checking | Robot model, environment model, candidate path | CollisionCheckResult | SimulationWorker |
| Kinematics Solver | Target pose, robot URDF, constraints | IKResult | ControlWorker |
| Trajectory Optimization | Waypoints, constraints, objective function | Optimized JointTrajectory | ControlWorker |
| Validation | JointTrajectory, safety constraints | ValidationResult | SimulationWorker |
| Execution | Validated JointTrajectory | Execution status | ControlWorker |

## Data Model (TypeScript)

```typescript
interface MotionPlan {
  planId: string;
  robotId: string;
  startState: RobotState;
  goalState: RobotState;
  constraints: PathConstraint[];
  trajectory: JointTrajectory;
  collisionCheck: CollisionCheckResult;
  ikResult: IKResult;
  optimizerConfig: OptimizerConfig;
  validationResult: ValidationResult;
  computationTimeMs: number;
  createdTimestamp: bigint;
}

interface RobotState {
  jointPositions: number[];
  jointVelocities: number[];
  jointEfforts: number[];
  pose: Pose;
  timestamp: bigint;
}

interface Pose {
  position: Vector3;
  orientation: Quaternion;
  frameId: string;
}

interface JointTrajectory {
  jointNames: string[];
  waypoints: Waypoint[];
  trajectoryType: "joint_space" | "cartesian_space" | "hybrid";
  duration: number;
  maxVelocity: number;
  maxAcceleration: number;
}

interface Waypoint {
  positions: number[];
  velocities: number[];
  accelerations: number[];
  efforts: number[];
  timeFromStart: number;
  pose?: Pose;
}

interface CollisionCheckResult {
  collisionDetected: boolean;
  collisionPairs: CollisionPair[];
  minimumDistance: number;
  checkedLinks: string[];
  checkedObjects: string[];
}

interface CollisionPair {
  linkA: string;
  linkB: string;
  distance: number;
  contactPointA: Vector3;
  contactPointB: Vector3;
  contactNormal: Vector3;
}

interface IKResult {
  solutionFound: boolean;
  jointPositions: number[];
  solutionQuality: number;
  iterations: number;
  residualError: number;
  multipleSolutions: number[][];
  singularityDetected: boolean;
}

interface PathConstraint {
  type: "joint_limit" | "velocity_limit" | "acceleration_limit" | "force_limit" |
        "collision_avoidance" | "singularity_avoidance" | "smoothness" |
        "time_optimal" | "energy_minimal" | "cartesian_path";
  weight: number;
  tolerance: number;
  parameters: Record<string, unknown>;
}

interface ValidationResult {
  isValid: boolean;
  checks: ValidationCheck[];
  warnings: string[];
  errors: string[];
  simulatedOutcome: string;
}

interface ValidationCheck {
  checkType: string;
  passed: boolean;
  value: number;
  threshold: number;
  details: string;
}

interface OptimizerConfig {
  algorithm: "qp" | "spline" | "gradient_descent" | "CHOMP" | "STOMP" | "TOPP";
  maxIterations: number;
  convergenceTolerance: number;
  timeHorizon: number;
  discretizationSteps: number;
  smoothnessWeight: number;
  obstacleWeight: number;
  goalWeight: number;
}

interface Obstacle {
  id: string;
  type: "box" | "sphere" | "cylinder" | "mesh" | "octree";
  pose: Pose;
  geometry: Geometry;
  isDynamic: boolean;
  velocity?: Vector3;
  predictedTrajectory?: JointTrajectory;
}

interface Geometry {
  box?: BoxGeometry;
  sphere?: SphereGeometry;
  cylinder?: CylinderGeometry;
  mesh?: MeshGeometry;
}

interface BoxGeometry {
  size: Vector3;
}

interface SphereGeometry {
  radius: number;
}

interface CylinderGeometry {
  radius: number;
  height: number;
}

interface MeshGeometry {
  filePath: string;
  scale: Vector3;
}

interface ReplanConfig {
  triggerOnCollision: boolean;
  triggerOnPathDeviation: boolean;
  deviationThreshold: number;
  maxReplanAttempts: number;
  replanStrategy: "full" | "local" | "lazy";
}

interface ExecutionStatus {
  planId: string;
  status: "pending" | "executing" | "completed" | "paused" | "aborted" | "error";
  currentWaypointIndex: number;
  progress: number;
  startTimestamp: bigint;
  elapsedMs: number;
  errorMessage?: string;
}
```

## Core Concepts / Operations

| Operation | Input | Output | Description |
|-----------|-------|--------|-------------|
| plan_trajectory | startState, goalState, constraints | MotionPlan | Computes a full motion plan from start to goal respecting all constraints |
| solve_ik | targetPose, robotModel, constraints | IKResult | Solves inverse kinematics for a target end-effector pose |
| check_collisions | JointTrajectory, obstacles | CollisionCheckResult | Checks a trajectory for collisions against all registered obstacles |
| optimize_path | JointTrajectory, constraints, config | JointTrajectory | Optimizes a trajectory for smoothness, time, or energy subject to constraints |
| validate_plan | MotionPlan | ValidationResult | Validates a motion plan against safety constraints and runs simulation verification |
| execute_plan | MotionPlan | ExecutionStatus | Sends validated trajectory to the robot controller for execution |
| replan_on_obstacle | MotionPlan, Obstacle | MotionPlan | Triggers replanning when a new obstacle is detected in the robot path |
| smooth_trajectory | JointTrajectory, smoothnessWeight | JointTrajectory | Applies trajectory smoothing to reduce jerk and acceleration peaks |
| compute_workspace | robotModel | WorkspaceVolume | Computes the reachable workspace of the robot given joint limits |

## Internal Interfaces

| Interface | Provider | Consumer | Description |
|-----------|----------|----------|-------------|
| ICollisionChecker | Motion Planning | ControlWorker | Checks robot link geometries against environment obstacles |
| IIKSolver | Motion Planning | ControlWorker | Solves inverse kinematics for target poses |
| ITrajectoryOptimizer | Motion Planning | ControlWorker | Optimizes trajectories for smoothness, time, or energy |
| IPlanValidator | Motion Planning | SimulationWorker | Validates plans against safety constraints via simulation |
| IReplanner | Motion Planning | ControlWorker | Triggers and executes replanning on obstacle detection or path deviation |

## Events

| ROB.EventType |      Produced When | Fields |
|-----------|--------------|--------|
| ROB.MotionPlanRequested |      A motion planning request is submitted | plan_id, robot_id, start_state, goal_state, constraint_count, timeout_ms |
| ROB.MotionPlanComputed |      A motion plan is successfully computed | plan_id, robot_id, waypoint_count, trajectory_length, computation_time_ms, algorithm_used |
| ROB.MotionPlanValidated |      A motion plan passes or fails validation | plan_id, is_valid, simulated_outcome, collision_checks_passed, warning_count |
| ROB.MotionPlanExecuted |      A motion plan begins execution on hardware | plan_id, robot_id, trajectory_duration, safety_gate_passed, executor_id |
| ROB.MotionPlanCompleted |      Motion plan execution finishes | plan_id, robot_id, status, actual_duration_ms, deviation_max, success |
| ROB.ObstacleDetected |      A new obstacle is detected in the robot workspace | obstacle_id, obstacle_type, position, is_dynamic, distance_to_robot, replan_triggered |
| ROB.MotionPlanAborted |      Motion plan execution is aborted | plan_id, robot_id, reason, current_state, safety_layer_triggered, recovery_action |
| ROB.IKSolutionFailed |      Inverse kinematics solver cannot find a valid solution | plan_id, target_pose, robot_model, constraints, iterations, residual_error |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|----------|
| ROB-MOT-001 | IK failure â€” inverse kinematics solver cannot find a valid joint configuration for the target pose | Error | Report IK failure with residual error. Suggest alternative goal poses within reachable workspace. Log target pose and constraints. |
| ROB-MOT-002 | Collision unavoidable â€” no collision-free path exists between start and goal given current obstacles | Critical | Report planning failure. Generate collision report with closest approach distances. Suggest goal relaxation or obstacle removal. |
| ROB-MOT-003 | Planning timeout â€” motion planner exceeds configurable time limit | Error | Return best trajectory found so far if valid. If no partial solution exists, report timeout. Increase allocated compute or simplify constraints. |
| ROB-MOT-004 | Plan validation failure â€” trajectory fails simulation-based safety validation | Critical | Block execution. Report specific validation failures (collision, joint limit violation, singularity). Require re-plan with corrected constraints. |
| ROB-MOT-005 | Singularity encountered â€” robot approaches kinematic singularity during trajectory execution | Warning | Reduce velocity through singularity region. If unrecoverable, abort plan and re-route around singularity. Log singularity configuration for analysis. |
| ROB-MOT-006 | Path deviation detected â€” robot deviates from planned trajectory beyond deviation threshold | Warning | Pause execution. Evaluate deviation magnitude. If within replan threshold, trigger local replanning. If exceeded, abort and escalate. |
| ROB-MOT-007 | Joint limit violation â€” trajectory exceeds position, velocity, or acceleration joint limits | Error | Clamp trajectory to joint limits during optimization. If violation persists, mark plan as invalid. Require constraint-aware re-plan. |
| ROB-MOT-008 | Obstacle motion prediction failure â€” dynamic obstacle trajectory cannot be predicted for collision checking | Warning | Use worst-case obstacle occupancy volume. Increase safety margin. Reduce planning speed. Log prediction failure. |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| ROB-MOT-I-001 | Simulation before execution â€” no motion plan may execute on physical hardware without passing simulation validation | Validation gate before execution. Simulation failure blocks deployment and triggers re-plan. |
| ROB-MOT-I-002 | Deterministic planning for safety-critical paths â€” same input must produce identical trajectory output for safety-critical operations | Seed all RNG in planners deterministically. Use fixed collision mesh sampling. Hash-validation of plans for audit. |
| ROB-MOT-I-003 | Collision-free guarantee â€” every executed trajectory must have zero collisions against static and known dynamic obstacles | Collision check at validation stage includes swept-volume analysis. Dynamic obstacles use conservative prediction. |
| ROB-MOT-I-004 | Joint limit protection â€” trajectory joint positions, velocities, and accelerations must remain within robot-specified limits | Saturation check at optimization output. Limit violations trigger validation failure. |
| ROB-MOT-I-005 | Monotonic progress â€” execution must make monotonic progress along the trajectory; backtracking is prohibited unless in replan | Waypoint index is strictly increasing. Reversal requires full abort and re-plan. |
| ROB-MOT-I-006 | Bounded replanning â€” replanning must complete within a configurable deadline to maintain real-time operation | Replan timer guards. Deadline miss triggers fallback to safe stop trajectory. |

## Design DNA

| Rule | Assessment |
|------|-----------|
| R1 - Modulsingularity | Each motion planning concern (collision checking, IK, trajectory optimization, validation, execution) is a separate module with a single responsibility |
| R2 - Dependency Order | Planner internal state (search trees, optimization variables) is encapsulated; consumers interact through MotionPlan interface only |
| R3 - DRY | Collision checking, IK solving, trajectory optimization, and validation are orthogonal â€” each can be used independently or composed |
| R4 - Builder Pattern | Planner supports polymorphic algorithm selection (CHOMP, STOMP, gradient descent, QP) through a common IPlanner interface |
| R5 - Liskov Substitution | All IK solver implementations conform to the same IIKSolver interface and produce IKResult regardless of solver type |
| R6 - DI over Singletons | Motion planning exposes narrow interfaces (ICollisionChecker, IIKSolver, ITrajectoryOptimizer, IPlanValidator) for testability |
| R9 - Deterministic | Same planning input must produce identical trajectory output for safety-critical paths; non-deterministic planning prohibited for L4+ paths |
| R10 - Simpler Over Complex | Default to joint-space planning with cubic splines. Use Cartesian or hybrid only when end-effector pose constraints require it |
| R13 - Design for Failure | Planning failures preserve search state for debugging. IK failure returns best-effort results. Collision-unavoidable returns closest approach analysis |
| R14 - Paved Path | Paved path: set goal â†’ check collisions â†’ solve IK â†’ optimize â†’ validate â†’ execute. Alternative planners available for specialized domains |
| R15 - Open/Closed | Each planner module has independently testable input/output contracts. Plans are verifiable against ground-truth simulation outcomes |

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
| Bible/07-Domains/Robotics/000-Overview.md | Domain overview â€” Motion Planning is a core Robotics capability |
| Bible/07-Domains/Robotics/001-ROS-Integration.md | ROS Integration â€” provides transport for motion plan commands and execution feedback |
| Bible/07-Domains/Robotics/002-Sensor-Fusion.md | Sensor Fusion â€” provides state estimates used as input for motion planning |
| Physics/005-Events.md | Evidence â€” all motion planning operations produce Events |
| Physics/007-Capabilities.md | Capabilities â€” motion planning is a bounded capability with compute limits |
| Physics/010-Execution.md | Execution â€” motion plans execute as control loops with real-time constraints |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001â€“010 â€” philosophical grounding for safety-first planning |
