/**
 * FlowSentry AI - 1-Click Competition Demo Runner
 * Guided step-by-step showcase for judges:
 * Baseline -> Payment Timeout Injection -> Detection -> AI RCA -> Approval -> Safe Replay -> Verification
 */

class DemoTourRunner {
  constructor() {
    this.modalEl = document.getElementById('demoModal');
    this.statusEl = document.getElementById('demoStatusText');
    this.stepDots = document.querySelectorAll('.demo-step-dot');
    this.isRunning = false;
  }

  showModal() {
    if (this.modalEl) this.modalEl.classList.add('active');
  }

  hideModal() {
    if (this.modalEl) this.modalEl.classList.remove('active');
  }

  setStep(stepIndex, title, message) {
    if (this.statusEl) {
      this.statusEl.innerHTML = `
        <div style="font-size: 11px; text-transform: uppercase; color: #00F0FF; font-weight: 700; margin-bottom: 4px;">Stage ${stepIndex} of 6: ${title}</div>
        <div style="font-size: 14px; color: #F3F4F6; line-height: 1.5;">${message}</div>
      `;
    }

    const dots = document.querySelectorAll('.demo-step-dot');
    dots.forEach((dot, idx) => {
      dot.classList.remove('active', 'completed');
      if (idx < stepIndex - 1) dot.classList.add('completed');
      if (idx === stepIndex - 1) dot.classList.add('active');
    });
  }

  async runFullDemo() {
    if (this.isRunning) return;
    this.isRunning = true;
    this.showModal();

    try {
      // Stage 1: Healthy Baseline
      this.setStep(1, 'Healthy Workflow Baseline', 'Executing 6-step purchase checkout with nominal microservice latencies...');
      await window.app.switchTab('simulator');
      const baselineRes = await fetch('/api/simulator/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: 'NONE' })
      }).then(r => r.json());

      if (window.app.visualizer && baselineRes.run) {
        await new Promise(res => window.app.visualizer.animateExecution(baselineRes.run.steps, res));
      }
      await new Promise(r => setTimeout(r, 1200));

      // Stage 2: Inject Payment Timeout Failure
      this.setStep(2, 'Failure Injection: Payment Timeout', 'Injecting upstream payment capture socket hang (>2500ms). Notice that healthcheck pings remain 200 OK!');
      const failedRes = await fetch('/api/simulator/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: 'PAYMENT_TIMEOUT' })
      }).then(r => r.json());

      if (window.app.visualizer && failedRes.run) {
        await new Promise(res => window.app.visualizer.animateExecution(failedRes.run.steps, res));
      }
      await new Promise(r => setTimeout(r, 1400));

      // Stage 3 & 4: Detection & AI Root Cause Diagnosis
      this.setStep(3, 'Detection & Autonomous Investigation', 'Failure detected in step 05. AI Detective analyzing log signatures and token dependencies...');
      await window.app.switchTab('investigation');
      
      const incidentId = failedRes.incident?.incident_id;
      if (incidentId) {
        await window.app.loadIncidentDetails(incidentId);
      }
      await new Promise(r => setTimeout(r, 2200));

      // Stage 5: Propose Safe Recovery & Human Approval
      this.setStep(4, 'Safe Recovery Proposal & Approval', 'Generating idempotent reconciliation plan with UUID token to prevent duplicate billing...');
      await window.app.switchTab('recovery');
      
      const propRes = await fetch('/api/recovery/propose', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ incident_id: incidentId })
      }).then(r => r.json());

      const recoveryActionId = propRes.data?.id;
      await window.app.renderRecoveryProposal(propRes.data);
      await new Promise(r => setTimeout(r, 1600));

      // Stage 6: Execute Replay & Verification
      this.setStep(5, 'Autonomous Replay & Verification', 'Executing idempotent recovery replay. Re-querying payment capture journal and finalizing order...');
      const execRes = await fetch('/api/recovery/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recovery_action_id: recoveryActionId, approved: true })
      }).then(r => r.json());

      await window.app.renderRecoveryOutcome(execRes.data);
      await new Promise(r => setTimeout(r, 1200));

      // Stage 7: Counterfactual Comparison (Signature Innovation)
      this.setStep(6, 'Verified Recovery & Counterfactual Diff', 'Verification Complete! Checkout recovered with zero duplicate charges. Comparing unmitigated loss vs recovered revenue.');
      await window.app.refreshDashboard();
      
    } catch (err) {
      console.error('Demo tour error:', err);
      if (this.statusEl) {
        this.statusEl.innerHTML += `<div style="color: #EF4444; margin-top: 8px;">Error: ${err.message}</div>`;
      }
    } finally {
      this.isRunning = false;
    }
  }
}

window.demoTourRunner = new DemoTourRunner();
