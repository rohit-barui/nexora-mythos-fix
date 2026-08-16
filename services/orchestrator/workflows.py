from temporalio import workflow

from services.orchestrator.activities import (
    ActivityContext,
    execute_activity,
    rollback_activity,
    snapshot_activity,
)

with workflow.unsafe.imports_passed_through():
    pass


@workflow.defn(name="remediation_workflow")
class RemediationWorkflow:
    """
    Governed Remediation Temporal Workflow.
    snapshot -> execute -> verify -> rollback (on failure) -> result
    """

    @workflow.run
    async def run(self, context: ActivityContext) -> dict:
        snapshots = await workflow.execute_activity(
            snapshot_activity,
            context,
            start_to_close_timeout=workflow.Duration.from_seconds(60),
        )
        workflow.logger.info("Snapshots created: %s", snapshots)

        execution = await workflow.execute_activity(
            execute_activity,
            context,
            start_to_close_timeout=workflow.Duration.from_seconds(300),
        )
        workflow.logger.info("Execution result: %s", execution["overall_status"])

        if execution["overall_status"] == "ROLLED_BACK":
            rollbacks = await workflow.execute_activity(
                rollback_activity,
                context,
                execution,
                start_to_close_timeout=workflow.Duration.from_seconds(120),
            )
            execution["rollbacks"] = rollbacks

        return execution


@workflow.defn(name="approval_workflow")
class ApprovalWorkflow:
    """
    Human-in-the-Loop approval workflow.
    Signals the approval decision and transitions to execution when approved.
    """

    def __init__(self) -> None:
        self.approval_decision: str | None = None

    @workflow.signal
    async def submit_approval(self, decision: str) -> None:
        self.approval_decision = decision

    @workflow.run
    async def run(self, context: ActivityContext) -> dict:
        await workflow.wait_condition(lambda: self.approval_decision is not None)
        if self.approval_decision == "APPROVED":
            return await workflow.execute_activity(
                execute_activity,
                context,
                start_to_close_timeout=workflow.Duration.from_seconds(300),
            )
        return {"overall_status": "REJECTED_BY_HUMAN", "actions": []}
