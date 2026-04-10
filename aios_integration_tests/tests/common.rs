use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::Duration;
use std::pin::Pin;
use std::future::Future;
use uuid::Uuid;

use aios_core::capability::Capability;
use aios_core::action::Action;
use aios_core::policy::PolicyEvaluator;

use aios_context_resolver::{IntentMeta, IntentOrigin, InjectionRisk, AgentContext, AgentClass};

use aios_policy::engine::DefaultPolicyEvaluator;
use aios_policy::VerifiedPolicyDecision;

use aios_executor::executor::{Executor, DefaultExecutor, ExecutionRequest, ExecutionOutcome, ConfirmationHandler};
use aios_executor::config::ExecutorConfig;
use aios_executor::sandbox::{SandboxAdapter, SandboxRegistry, SandboxResult, SandboxError, ExecutionContext, SandboxId};
use aios_executor::audit::{AuditLog, AuditEntry};
use aios_executor::capability::CapabilityEnforcer;
use aios_executor::error::ExecutorError;

// ─── Mocks ───────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct MockSandbox {
    pub is_healthy: bool,
    pub call_count: Arc<Mutex<usize>>,
    pub should_crash: bool,
}

impl MockSandbox {
    pub fn new() -> Self {
        Self {
            is_healthy: true,
            call_count: Arc::new(Mutex::new(0)),
            should_crash: false,
        }
    }
}

impl SandboxAdapter for MockSandbox {
    fn run_in_sandbox(
        &self,
        _action: &Action,
        _ctx: &ExecutionContext,
    ) -> Pin<Box<dyn Future<Output = Result<SandboxResult, SandboxError>> + Send + '_>> {
        let should_crash = self.should_crash;
        let call_count = self.call_count.clone();
        Box::pin(async move {
            *call_count.lock().await += 1;
            if should_crash {
                return Err(SandboxError::ExecutionFailed("Sandbox crashed mid-execution".to_string()));
            }
            Ok(SandboxResult {
                exit_code: 0,
                stdout: "Success".to_string(),
                stderr: "".to_string(),
                duration_ms: 10,
            })
        })
    }

    fn force_kill(
        &self,
        _sandbox_id: &SandboxId,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {})
    }

    fn health_check(&self) -> bool {
        self.is_healthy
    }

    fn name(&self) -> &str {
        "mock_sandbox"
    }
}

pub struct MockAuditLog {
    last_entry: Arc<Mutex<Option<AuditEntry>>>,
    pub should_fail: bool,
}

impl MockAuditLog {
    pub fn new() -> Self {
        Self {
            last_entry: Arc::new(Mutex::new(None)),
            should_fail: false,
        }
    }
}

impl AuditLog for MockAuditLog {
    fn emit(&self, entry: AuditEntry) -> Result<(), ExecutorError> {
        if self.should_fail {
            return Err(ExecutorError::AuditLogFailed);
        }
        if let Ok(mut last) = self.last_entry.try_lock() {
            *last = Some(entry);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct MockCapabilityEnforcer {}

impl CapabilityEnforcer for MockCapabilityEnforcer {
    fn check(&self, _agent_id: &str, _action: &Action) -> Result<(), ExecutorError> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct MockConfirmationHandler {}

impl ConfirmationHandler for MockConfirmationHandler {
    fn user_confirms(
        &self,
        _request_id: &Uuid,
        _agent_id: &str,
        _action: &Action,
        _warnings: &[String],
    ) -> bool {
        true
    }
}

// ─── TestPipeline ───────────────────────────────────────────────────────────

pub struct TestPipeline {
    resolver: aios_context_resolver::resolver::DefaultContextResolver,
    policy: Arc<Mutex<DefaultPolicyEvaluator>>,
    executor: DefaultExecutor,
    fail_resolver: bool,
    fail_policy: bool,
}

impl TestPipeline {
    pub fn new() -> Self {
        Self::build(false, false, false, false)
    }

    pub fn with_failing_audit_sink() -> Self {
        Self::build(false, false, true, false)
    }

    pub fn with_crashing_sandbox() -> Self {
        Self::build(false, false, false, true)
    }

    pub fn with_failing_resolver() -> Self {
        Self::build(true, false, false, false)
    }

    pub fn with_failing_policy_engine() -> Self {
        Self::build(false, true, false, false)
    }

    fn build(fail_resolver: bool, fail_policy: bool, fail_audit: bool, crash_sandbox: bool) -> Self {
        let resolver = aios_context_resolver::resolver::DefaultContextResolver::new(aios_context_resolver::config::ResolverConfig::default_config());
        let policy = Arc::new(Mutex::new(DefaultPolicyEvaluator::new()));
        
        let mut sandbox = MockSandbox::new();
        sandbox.should_crash = crash_sandbox;
        
        let mut audit = MockAuditLog::new();
        audit.should_fail = fail_audit;

        let mut config = ExecutorConfig::default_config();
        config.timeouts.risk_low_ms = 50; 
        
        let mut registry = SandboxRegistry::new("mock_sandbox".to_string());
        registry.register(Box::new(sandbox));
        
        let executor = DefaultExecutor::new(
            config,
            registry,
            Box::new(audit),
            Box::new(MockConfirmationHandler {}),
            Box::new(MockCapabilityEnforcer {}),
        );

        Self {
            resolver,
            policy,
            executor,
            fail_resolver,
            fail_policy,
        }
    }

    // A simulated pipeline execution returning an Executor result or error
    pub async fn run(&self, action: Action, meta: IntentMeta, agent: AgentContext) -> Result<ExecutionOutcome, String> {
        let caps = vec![
            Capability::ReadOnly,
            Capability::SystemInfo,
            Capability::FileDelete,
            Capability::PackageInstall,
        ];
        self.run_inner(action, meta, agent, false, caps.into_iter().collect()).await
    }

    pub async fn run_with_caps(&self, action: Action, meta: IntentMeta, agent: AgentContext, caps: Vec<Capability>) -> Result<ExecutionOutcome, String> {
        self.run_inner(action, meta, agent, false, caps.into_iter().collect()).await
    }

    pub async fn run_dry(&self, action: Action, meta: IntentMeta, agent: AgentContext) -> Result<ExecutionOutcome, String> {
        let caps = vec![
            Capability::ReadOnly,
            Capability::SystemInfo,
            Capability::FileDelete,
            Capability::PackageInstall,
        ];
        self.run_inner(action, meta, agent, true, caps.into_iter().collect()).await
    }

    async fn run_inner(&self, action: Action, meta: IntentMeta, agent: AgentContext, dry_run: bool, caps: std::collections::HashSet<Capability>) -> Result<ExecutionOutcome, String> {
        if self.fail_resolver {
            return Err("Context resolver unavailable".into());
        }

        use aios_context_resolver::resolver::ContextResolver;
        let resolved = self.resolver.resolve(&action, &meta, &agent)
            .map_err(|e| format!("Resolver error: {:?}", e))?;

        if self.fail_policy {
            return Err("Policy engine unavailable".into());
        }

        let ctx = aios_core::policy::PolicyContext {
            user: agent.agent_id.clone(),
            working_dir: std::path::PathBuf::from("/tmp"),
            time: chrono::Utc::now(),
            system_state: aios_core::policy::SystemState::Extensions(std::collections::HashMap::new()),
            previous_actions: vec![],
            rate_limit: aios_core::policy::RateLimit {
                max_actions_per_minute: 2, // Low for testing cooldown
                window_seconds: 60,
            },
        };

        let request_id = Uuid::new_v4();
        let decision: VerifiedPolicyDecision = {
            let mut policy_lock = self.policy.lock().await;
            policy_lock.set_capabilities(caps);
            let d = policy_lock.evaluate_verified(&resolved.original, &ctx, request_id);
            d
        };
        
        let req = ExecutionRequest {
            version: 1,
            request_id,
            agent_id: agent.agent_id.clone(),
            action: action.clone(), // Normally we pass resolved action but action is sufficient for tests
            decision,
            dry_run,
            idempotency_key: None,
        };

        match self.executor.execute(req).await {
            Ok(res) => {
                if matches!(res.outcome, ExecutionOutcome::Succeeded) {
                    Ok(res.outcome)
                } else {
                    // Include the outcome in the error so we can see why it failed
                    Err(format!("Execution failed with outcome: {:?}", res.outcome))
                }
            },
            Err(e) => Err(format!("Executor error: {:?}", e)),
        }
    }
}

pub fn make_agent(id: &str) -> AgentContext {
    AgentContext {
        agent_id: id.to_string(),
        class: AgentClass::new("standard"),
        session_id: None,
    }
}

pub fn make_meta(confidence: f32) -> IntentMeta {
    IntentMeta {
        agent_id: "test".to_string(),
        confidence,
        origin: IntentOrigin::DirectPrompt,
        injection_risk: InjectionRisk::Clean,
    }
}

pub fn make_meta_high_risk() -> IntentMeta {
    IntentMeta {
        agent_id: "test".to_string(),
        confidence: 0.95,
        origin: IntentOrigin::DirectPrompt,
        injection_risk: InjectionRisk::HighRisk { reason: "risk".to_string() },
    }
}

pub fn make_query_action() -> Action {
    use aios_core::params::{QuerySystemInfoParams, SystemInfoKind};
    use aios_core::action::CoreAction;
    Action::Core(CoreAction::QuerySystemInfo(QuerySystemInfoParams {
        filters: vec![SystemInfoKind::Cpu],
        include_all: false,
    }))
}
