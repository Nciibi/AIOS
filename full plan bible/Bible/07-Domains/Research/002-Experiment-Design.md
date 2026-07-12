# AIOS Bible â€” Domains
## Research â€” 002: Experiment Design

| Property | Value |
|----------|-------|
| Status | Active |
| Version | 1.0.0 |
| Category | Bible â€” Domains |
| Document ID | AIOS-BBL-007-RES-002 |
| Source Laws | Law 4 â€” Law of Evidence, Law 7 â€” Law of Capability Bounds |
| Source Physics | Physics/005-Events.md, Physics/007-Capabilities.md, Physics/012-Experience.md |
| Supersedes | Nothing |
| Superseded By | Nothing |
| Amended By | RFC |

## Purpose

The Experiment Design engine enables AIOS to formalize hypotheses, identify variables, select appropriate experimental designs, calculate sample sizes, choose statistical methodologies, mitigate biases, and generate reproducible protocols. It ensures that AIOS-generated experiments meet scientific standards for validity, reproducibility, and ethical conduct.

## Architecture

```
hypothesis_formalization â”€â”€> variable_definition â”€â”€> design_selection â”€â”€> sample_calculation â”€â”€> protocol_generation â”€â”€> ethics_review
        â”‚                          â”‚                        â”‚                     â”‚                      â”‚                   â”‚
        v                          v                        v                     v                      v                   v
   Hypothesis               VariableDef             ExperimentDesign         SampleSizeCalc          Protocol           EthicsApproval
```

Each step validates the previous. The pipeline may loop back if ethics review or feasibility checks fail.

## Data Model

```typescript
interface ExperimentDesign {
  experimentId: string;
  title: string;
  hypothesisId: string;
  designType: DesignType;
  variables: VariableDefinition[];
  sampleSizeCalculation: SampleSizeCalculation;
  statisticalMethod: StatisticalMethod;
  biasMitigationPlan: BiasMitigationPlan;
  protocol: Protocol;
  ethicsReview: EthicsReview;
  status: ExperimentStatus;
  createdAt: Date;
}

interface Hypothesis {
  hypothesisId: string;
  researchQuestion: string;
  nullHypothesis: string;
  alternativeHypothesis: string;
  directionality: Directionality;
  isFalsifiable: boolean;
  isTestable: boolean;
  scope: string;
  assumptions: string[];
}

interface VariableDefinition {
  variableId: string;
  name: string;
  type: VariableType;
  role: VariableRole;
  measurementScale: MeasurementScale;
  operationalDefinition: string;
  units?: string;
  allowedValues?: string[];
  constraints: string[];
}

interface SampleSizeCalculation {
  calculationId: string;
  method: string;
  effectSize: number;
  power: number;
  alpha: number;
  requiredSampleSize: number;
  feasibleSampleSize?: number;
  isFeasible: boolean;
  assumptions: string[];
  formula: string;
}

interface StatisticalMethod {
  methodId: string;
  primaryTest: string;
  assumptions: string[];
  assumptionViolations: string[];
  robustnessChecks: string[];
  effectSizeMeasure: string;
  correctionForMultipleComparisons?: string;
}

interface BiasMitigationPlan {
  planId: string;
  randomizationMethod?: string;
  blindingLevel: BlindingLevel;
  confoundingControls: ConfoundingControl[];
  selectionBiasControls: string[];
  measurementBiasControls: string[];
  attritionPlan: string;
  reportingGuidelines: string[];
}

interface Protocol {
  protocolId: string;
  steps: ProtocolStep[];
  materials: string[];
  equipment: string[];
  safetyProcedures: string[];
  dataCollectionPlan: string;
  qualityChecks: QualityCheck[];
  estimatedDuration: string;
  reproducibilityScore: number;
}

interface EthicsReview {
  reviewId: string;
  requiresApproval: boolean;
  informedConsentRequired: boolean;
  dataPrivacyAssessment: string;
  riskLevel: RiskLevel;
  approvalGranted: boolean;
  reviewNotes: string[];
  reviewedAt?: Date;
}

enum DesignType {
  RCT = "randomized_controlled_trial",
  QuasiExperimental = "quasi_experimental",
  WithinSubjects = "within_subjects",
  BetweenSubjects = "between_subjects",
  Factorial = "factorial",
  Crossover = "crossover",
  Longitudinal = "longitudinal",
  CrossSectional = "cross_sectional",
  CaseControl = "case_control",
  Cohort = "cohort"
}

enum VariableType {
  Independent = "independent",
  Dependent = "dependent",
  Control = "control",
  Confounding = "confounding",
  Moderator = "moderator",
  Mediator = "mediator"
}

enum VariableRole {
  Manipulated = "manipulated",
  Measured = "measured",
  HeldConstant = "held_constant",
  Random = "random"
}

enum MeasurementScale {
  Nominal = "nominal",
  Ordinal = "ordinal",
  Interval = "interval",
  Ratio = "ratio"
}

enum Directionality {
  OneTailedGreater = "one_tailed_greater",
  OneTailedLess = "one_tailed_less",
  TwoTailed = "two_tailed"
}

enum BlindingLevel {
  None = "none",
  SingleBlind = "single_blind",
  DoubleBlind = "double_blind",
  TripleBlind = "triple_blind"
}

enum RiskLevel {
  Minimal = "minimal",
  Low = "low",
  Medium = "medium",
  High = "high"
}

enum ExperimentStatus {
  Draft = "draft",
  HypothesisFormalized = "hypothesis_formalized",
  VariablesDefined = "variables_defined",
  DesignSelected = "design_selected",
  SampleCalculated = "sample_calculated",
  ProtocolGenerated = "protocol_generated",
  EthicsApproved = "ethics_approved",
  ReadyForExecution = "ready_for_execution"
}

interface ProtocolStep {
  stepNumber: number;
  description: string;
  duration: string;
  dependencies: number[];
  failureContingency: string;
}

interface QualityCheck {
  checkId: string;
  type: string;
  criteria: string;
  frequency: string;
}

interface ConfoundingControl {
  confounder: string;
  identificationMethod: string;
  controlMethod: string;
}
```

## Core Concepts / Operations

| Operation | Input | Output | Description |
|-----------|-------|--------|-------------|
| design_experiment | hypothesis, constraints | ExperimentDesign | Generates a complete experiment design from a hypothesis |
| formalize_hypothesis | researchQuestion | Hypothesis | Produces falsifiable null and alternative hypotheses |
| identify_variables | hypothesis, domain | VariableDefinition[] | Identifies independent, dependent, control, and confounding variables |
| calculate_sample_size | effectSize, power, alpha | SampleSizeCalculation | Computes required sample size using selected method |
| select_design | variables, constraints | DesignType | Recommends optimal experimental design |
| select_methodology | designType, variables | StatisticalMethod | Chooses statistical tests matching the design |
| mitigate_bias | designType, variables | BiasMitigationPlan | Generates bias mitigation strategies including blinding and randomization |
| generate_protocol | design, variables | Protocol | Produces step-by-step experimental protocol |
| review_ethics | protocol, domain | EthicsReview | Assesses ethical implications and required approvals |

## Internal Interfaces

| Interface | Provider | Consumer | Method | Description |
|-----------|----------|----------|--------|-------------|
| IHypothesisValidator | FalsifiabilityChecker | ExperimentDesigner | validate(hypothesis) | Validates hypothesis is falsifiable and testable |
| IVariableDetector | ConfoundingAnalyzer | ExperimentDesigner | detect(data, variables) | Identifies potential confounding variables |
| ISampleCalculator | PowerAnalysisEngine | ExperimentDesigner | calculate(effectSize, power, alpha) | Computes required sample size for statistical power |
| IDesignRecommender | DesignSelector | ExperimentDesigner | recommend(variables, constraints) | Suggests appropriate experimental design |
| IMethodologySelector | StatisticalEngine | ExperimentDesigner | select(designType, scale) | Chooses statistical tests matching design and measurement scale |
| IEthicsReviewer | EthicsCompliance | ExperimentDesigner | assess(protocol, domain) | Evaluates ethical compliance of proposed experiment |

## Events

| Event Type | Produced When | Fields |
|-----------|--------------|--------|
| Research.HypothesisFormalized | Hypothesis is validated and accepted | hypothesis_id, null_hypothesis, alternative_hypothesis, is_falsifiable |
| Research.VariablesIdentified | Variables are defined and categorized | design_id, independent_count, dependent_count, confounders_detected |
| Research.DesignSelected | Experimental design type is chosen | design_id, design_type, rationale, alternatives_considered |
| Research.SampleCalculated | Sample size calculation completes | calculation_id, required_size, feasible_size, power, alpha, effect_size |
| Research.ProtocolGenerated | Protocol is produced and validated | protocol_id, step_count, estimated_duration, reproducibility_score |
| Research.EthicsApproved | Ethics review is completed | review_id, risk_level, approval_granted, review_notes_count |
| Research.ExperimentDesigned | Full experiment design is completed and ready | experiment_id, hypothesis_id, design_type, status, design_duration_ms |

## Error Cases

| Code | Condition | Severity | Recovery |
|------|-----------|----------|---------|
| EXP-ERR-001 | Required sample size exceeds feasible population (infeasible) | High | Suggest alternative design (within-subjects, higher effect size target). If still infeasible, mark experiment as infeasible with documentation. |
| EXP-ERR-002 | Confounding variable detected that cannot be controlled or randomized | High | Flag as design limitation. Suggest statistical control (ANCOVA, matching). If uncontrolled, document as validity threat. |
| EXP-ERR-003 | Selected statistical methodology violates assumptions of the data | Medium | Test assumptions. If violated, suggest robust alternative or non-parametric equivalent. Document violation. |
| EXP-ERR-004 | Ethics review identifies unacceptable risk-to-benefit ratio | High | Block experiment. Provide detailed rationale. Escalate to human review. Experiment cannot proceed. |
| EXP-ERR-005 | Hypothesis is not falsifiable (tautological or untestable) | Medium | Return to formalization step. Suggest reframing. If not falsifiable, reject hypothesis. |
| EXP-ERR-006 | Required blinding level cannot be implemented in the given context | Medium | Document limitation. Implement partial blinding. Adjust confidence assessment accordingly. |
| EXP-ERR-007 | Protocol step depends on missing prerequisite equipment or materials | Medium | Flag dependency chain. Suggest alternatives. If critical, halt protocol generation. |
| EXP-ERR-008 | Effect size estimate required for sample calculation is unavailable | Low | Suggest using smallest effect size of interest (SESOI). If unavailable, recommend pilot study. |

## Invariants

| ID | Rule | Enforcement |
|----|------|-------------|
| EXP-I-001 | Every experiment must have a falsifiable hypothesis | Hypothesis validator rejects non-falsifiable hypotheses during formalization. |
| EXP-I-002 | Every design must declare all known biases and their mitigation strategy | Bias mitigation plan is mandatory. Missing plan blocks protocol generation. |
| EXP-I-003 | Sample size calculation must document assumptions and power analysis | Power analysis is mandatory. Effect size, alpha, and power must be reported. |
| EXP-I-004 | Ethics review is mandatory for all experiments involving data collection | Ethics check is gated. No experiment proceeds without ethics assessment. |
| EXP-I-005 | All experiments must be reproducible from their protocol and design records | Protocol must include step details, materials, equipment, and quality checks. Reproducibility score tracked. |

## Design DNA

| Rule | Compliance |
|------|-----------|
| R1 (Modulsingularity) | Each design step (hypothesis, variables, design, sample, protocol, ethics) is a separate module |
| R2 (Dependency Order) | Experiment Design depends on Literature Review for existing evidence; depends on Academy for protocol storage |
| R3 (DRY) | Hypothesis records stored once in Academy, referenced by all experiment artifacts |
| R4 (Builder Pattern) | ExperimentDesign and Protocol are built by step-by-step builders with validation at each stage |
| R5 (Liskov) | All IDesignRecommender implementations (clinical, social science, engineering) are interchangeable |
| R6 (DI over Singletons) | Statistical engine and ethics reviewer are injected as dependencies |
| R9 (Deterministic) | Same hypothesis and constraints produce identical design recommendations |
| R10 (Simpler Over Complex) | Default to simplest valid design (e.g., between-subjects over factorial unless justified) |
| R13 (Design for Failure) | Infeasible sample sizes produce documentation, not crashes; ethics blocks produce clear rejection reasons |
| R14 (Paved Path) | Single paved path: hypothesis -> variables -> design -> sample -> protocol -> ethics |
| R15 (Open/Closed) | New design types implement IDesignRecommender without modifying the pipeline |

## Related Documents

| Document | Relationship |
|---------|-------------|
| Research/000-Overview.md | Research domain overview â€” entities, capabilities, methodology |
| Research/001-Literature-Review.md | Literature Review â€” hypothesis generation from gap analysis |
| Research/003-Data-Analysis.md | Data Analysis â€” experiment data processing and statistical testing |
| Physics/005-Events.md | Evidence â€” all experiment design operations produce Events |
| Physics/007-Capabilities.md | Capabilities â€” compute bounds for power analysis |
| Physics/012-Experience.md | Experience â€” experiment outcomes contribute to AIOS learning |
| Bible/02-Core/Academy/000-Overview.md | Academy â€” experiment designs and protocols stored as knowledge artifacts |
| Bible/02-Core/DTS/000-Overview.md | DTS â€” confidence scoring for experimental results |
| Bible/02-Core/ROS/000-Overview.md | ROS â€” resource allocation for experiment execution |
| Bible/00-Foundations/001-AIOS-Philosophy.md | PHI-001â€“010 â€” philosophical grounding for empirical research |
| Bible/00-Foundations/003-Core-Principles.md | CPR-001â€“010 â€” core principles applied to experiment design |
