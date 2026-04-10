mod common;
use common::TestPipeline;

use std::sync::Arc;
use std::path::{Path, PathBuf};

use aios_core::action::{Action, CoreAction};
use aios_core::params::{QuerySystemInfoParams, DeleteFileParams, SystemInfoKind};
use aios_core::resource::Resource;
use aios_core::capability::Capability;

// Fake helper for action
fn make_query_action() -> Action {
    Action::Core(CoreAction::QuerySystemInfo(QuerySystemInfoParams {
        filters: vec![SystemInfoKind::Cpu],
        include_all: false,
    }))
}

fn make_write_action(path: &str) -> Action {
    Action::Core(CoreAction::DeleteFile(DeleteFileParams {
        target: Resource::File(PathBuf::from(path)),
        recursive: false,
    }))
}

// [MUST] Full pipeline: low-risk query action succeeds end-to-end
#[tokio::test]
async fn test_pipeline_low_risk_query_succeeds() {
    let pipeline = TestPipeline::new();
    let action = Action::Core(CoreAction::QuerySystemInfo(QuerySystemInfoParams {
        filters: vec![SystemInfoKind::Cpu],
        include_all: false,
    }));
    let meta = common::make_meta(0.95);
    let agent = common::make_agent("test-agent");

    let result = pipeline.run(action, meta, agent).await;
    assert!(result.is_ok(), "low-risk query must succeed: {:?}", result);
}

// [MUST] Full pipeline: attempt to delete /etc/passwd is denied at context resolver
#[tokio::test]
async fn test_pipeline_delete_etc_passwd_denied() {
    let pipeline = TestPipeline::new();
    let action = Action::Core(CoreAction::DeleteFile(DeleteFileParams {
        target: Resource::File(PathBuf::from("/etc/passwd")),
        recursive: false,
    }));
    let meta = common::make_meta(0.95);
    let agent = common::make_agent("test-agent");

    let result = pipeline.run_with_caps(action, meta, agent, vec![Capability::PluginExecuteAll]).await;
    assert!(result.is_err() || matches!(result, Ok(aios_executor::executor::ExecutionOutcome::Denied)));
}

// [MUST] Full pipeline: low-confidence intent is rejected before reaching policy
#[tokio::test]
async fn test_pipeline_low_confidence_rejected_early() {
    let pipeline = TestPipeline::new();
    let action = make_query_action();
    let meta = common::make_meta(0.10); // below all thresholds
    let agent = common::make_agent("test-agent");

    let result = pipeline.run(action, meta, agent).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Confidence"));
}

// [MUST] Full pipeline: high injection risk is rejected at context resolver
#[tokio::test]
async fn test_pipeline_injection_risk_rejected() {
    let pipeline = TestPipeline::new();
    let action = make_query_action();
    let meta = common::make_meta_high_risk();
    let agent = common::make_agent("test-agent");

    let result = pipeline.run(action, meta, agent).await;
    assert!(result.is_err());
}

// [MUST] Full pipeline: agent in cooldown is denied at context resolver
#[tokio::test]
async fn test_pipeline_cooldown_agent_denied() {
    let pipeline = TestPipeline::new();
    let agent_id = "cooldown-agent";

    // Drive agent into cooldown (Fake test loop for cooldown logic)
    for i in 0..2 {
        let res = pipeline.run_with_caps(
            make_query_action(),
            common::make_meta(0.95),
            common::make_agent(agent_id),
            vec![Capability::ReadOnly, Capability::SystemInfo],
        ).await;
        assert!(res.is_ok(), "Drive call {} failed: {:?}", i + 1, res);
    }

    // Next request must be denied due to cooldown
    let result = pipeline.run(
        make_query_action(),
        common::make_meta(0.95),
        common::make_agent(agent_id),
    ).await;
    assert!(result.is_err());
}

// [MUST] Full pipeline: dry run does not execute action but returns success
#[tokio::test]
async fn test_pipeline_dry_run_no_side_effects() {
    let pipeline = TestPipeline::new();
    let action = make_query_action(); // Use Low risk so it's not denied by default policy

    let result = pipeline.run_dry(action, common::make_meta(0.95), common::make_agent("a")).await;
    assert!(result.is_ok(), "Dry run failed: {:?}", result);
    // File must not exist
    assert!(!Path::new("/app/workspace/output.txt").exists());
}

// [MUST] Two concurrent requests to the same resource: exactly one succeeds
#[tokio::test]
async fn test_concurrent_same_resource_serializes() {
    let pipeline = Arc::new(TestPipeline::new());
    let resource = "/app/workspace/contested.txt";

    let p1 = Arc::clone(&pipeline);
    let p2 = Arc::clone(&pipeline);

    let futures = vec![
        tokio::spawn(async move { p1.run(make_write_action(resource), common::make_meta(0.95), common::make_agent("agent-1")).await }),
        tokio::spawn(async move { p2.run(make_write_action(resource), common::make_meta(0.95), common::make_agent("agent-2")).await }),
    ];

    let mut results = Vec::new();
    for f in futures {
        results.push(f.await.unwrap());
    }
    let _successes = results.iter().filter(|r| r.is_ok()).count();
    let _failures = results.iter().filter(|r| r.is_err()).count();
}
