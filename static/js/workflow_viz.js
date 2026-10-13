/**
 * FlowSentry AI - Workflow Visualizer
 * Connected nodes graph with directional arrows, live state transitions, and step logs inspector.
 */

class WorkflowVisualizer {
  constructor(containerId, logContainerId) {
    this.container = document.getElementById(containerId);
    this.logContainer = document.getElementById(logContainerId);
    this.currentSteps = [];
    this.defaultSteps = [
      { step_name: 'auth', step_label: 'User Auth', step_order: 1, status: 'IDLE', latency_ms: 0 },
      { step_name: 'cart', step_label: 'Shopping Cart', step_order: 2, status: 'IDLE', latency_ms: 0 },
      { step_name: 'inventory', step_label: 'Inventory Check', step_order: 3, status: 'IDLE', latency_ms: 0 },
      { step_name: 'payment_auth', step_label: 'Payment Auth', step_order: 4, status: 'IDLE', latency_ms: 0 },
      { step_name: 'payment_confirm', step_label: 'Payment Confirm', step_order: 5, status: 'IDLE', latency_ms: 0 },
      { step_name: 'order_create', step_label: 'Order Creation', step_order: 6, status: 'IDLE', latency_ms: 0 }
    ];
    this.render(this.defaultSteps);
  }

  render(steps = this.defaultSteps) {
    if (!this.container) return;
    this.currentSteps = steps;
    this.container.innerHTML = '';

    steps.forEach((step, idx) => {
      // Step Node Element
      const node = document.createElement('div');
      node.className = `workflow-node ${step.status.toLowerCase()}`;
      node.id = `node-${step.step_name}`;
      node.onclick = () => this.inspectStepLogs(step);

      let badgeClass = 'badge-skipped';
      if (step.status === 'SUCCESS') badgeClass = 'badge-success';
      else if (step.status === 'FAILED') badgeClass = 'badge-failed';
      else if (step.status === 'DEGRADED') badgeClass = 'badge-degraded';
      else if (step.status === 'RUNNING') badgeClass = 'badge-running';

      node.innerHTML = `
        <div class="node-header">
          <span class="node-index">0${step.step_order}</span>
          <span class="node-status-badge ${badgeClass}">${step.status}</span>
        </div>
        <div class="node-title">${step.step_label || step.step_name}</div>
        <div class="node-meta">
          <span>${step.latency_ms > 0 ? step.latency_ms + ' ms' : '--'}</span>
          <span>${step.error_code ? '⚠️ ' + step.error_code : (step.status === 'SUCCESS' ? '✓ OK' : '')}</span>
        </div>
      `;

      this.container.appendChild(node);

      // Connector Arrow (except last step)
      if (idx < steps.length - 1) {
        const connector = document.createElement('div');
        connector.className = `node-connector ${step.status === 'SUCCESS' ? 'active' : ''} ${step.status === 'FAILED' ? 'failed' : ''}`;
        connector.innerHTML = '➔';
        this.container.appendChild(connector);
      }
    });
  }

  inspectStepLogs(step) {
    if (!this.logContainer) return;
    const logs = step.logs || [`No logs recorded for step ${step.step_name}`];
    
    let html = `
      <div style="margin-bottom: 10px; border-bottom: 1px solid #1E2D4A; padding-bottom: 6px;">
        <span style="color: #00F0FF; font-weight: 700;">[Step: ${step.step_name}]</span>
        <span style="color: #94A3B8; margin-left: 8px;">Status: ${step.status}</span>
        <span style="color: #94A3B8; margin-left: 8px;">Latency: ${step.latency_ms}ms</span>
        ${step.error_message ? `<div style="color: #F87171; margin-top: 4px;">Error: ${step.error_message}</div>` : ''}
      </div>
    `;

    logs.forEach(log => {
      let cssClass = 'log-msg';
      if (log.includes('ERROR') || log.includes('FATAL') || log.includes('504') || log.includes('409') || log.includes('503')) {
        cssClass += ' error';
      } else if (log.includes('WARN')) {
        cssClass += ' warn';
      } else if (log.includes('200 OK') || log.includes('201 Created') || log.includes('RECONCILIATION') || log.includes('verified')) {
        cssClass += ' success';
      }

      html += `
        <div class="log-entry">
          <span class="log-time">[${new Date().toLocaleTimeString()}]</span>
          <span class="${cssClass}">${log}</span>
        </div>
      `;
    });

    this.logContainer.innerHTML = html;
    this.logContainer.scrollTop = this.logContainer.scrollHeight;
  }

  async animateExecution(steps, onComplete) {
    // Sequentially highlight each node running, then reveal final status
    for (let i = 0; i < steps.length; i++) {
      const step = steps[i];
      const nodeEl = document.getElementById(`node-${step.step_name}`);
      if (nodeEl) {
        nodeEl.className = 'workflow-node running';
        const badge = nodeEl.querySelector('.node-status-badge');
        if (badge) {
          badge.className = 'node-status-badge badge-running';
          badge.innerText = 'RUNNING';
        }
      }
      
      this.inspectStepLogs(step);
      // Brief simulated pause for visual UX
      await new Promise(r => setTimeout(r, 120));

      if (nodeEl) {
        let badgeClass = 'badge-skipped';
        if (step.status === 'SUCCESS') badgeClass = 'badge-success';
        else if (step.status === 'FAILED') badgeClass = 'badge-failed';
        else if (step.status === 'DEGRADED') badgeClass = 'badge-degraded';

        nodeEl.className = `workflow-node ${step.status.toLowerCase()}`;
        const badge = nodeEl.querySelector('.node-status-badge');
        if (badge) {
          badge.className = `node-status-badge ${badgeClass}`;
          badge.innerText = step.status;
        }
        const meta = nodeEl.querySelector('.node-meta');
        if (meta) {
          meta.innerHTML = `
            <span>${step.latency_ms > 0 ? step.latency_ms + ' ms' : '--'}</span>
            <span>${step.error_code ? '⚠️ ' + step.error_code : (step.status === 'SUCCESS' ? '✓ OK' : '')}</span>
          `;
        }
      }

      if (step.status === 'FAILED') break;
    }

    this.render(steps);
    if (onComplete) onComplete();
  }
}

window.WorkflowVisualizer = WorkflowVisualizer;
