/**
 * FlowSentry AI - Operational Charts Module
 * Renders dark-mode Chart.js visualizations for telemetry, SLA compliance, and failure breakdown.
 */

class FlowSentryCharts {
  constructor() {
    this.latencyChart = null;
    this.breakdownChart = null;
    this.slaChart = null;
  }

  initLatencyChart(canvasId, trendRuns = []) {
    const ctx = document.getElementById(canvasId);
    if (!ctx || !window.Chart) return;

    if (this.latencyChart) {
      this.latencyChart.destroy();
    }

    const labels = trendRuns.map((r, i) => `#${i + 1} (${r.scenario.substring(0, 8)})`);
    const data = trendRuns.map(r => r.total_latency_ms);
    const pointColors = trendRuns.map(r => r.status === 'SUCCESS' || r.status === 'RECOVERED' ? '#10B981' : '#EF4444');

    this.latencyChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: labels,
        datasets: [
          {
            label: 'Total Latency (ms)',
            data: data,
            borderColor: '#00F0FF',
            backgroundColor: 'rgba(0, 240, 255, 0.08)',
            borderWidth: 2,
            pointBackgroundColor: pointColors,
            pointRadius: 4,
            tension: 0.3,
            fill: true
          },
          {
            label: 'SLA Threshold (1200ms)',
            data: labels.map(() => 1200),
            borderColor: '#F59E0B',
            borderWidth: 1.5,
            borderDash: [5, 5],
            pointRadius: 0,
            fill: false
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            labels: { color: '#94A3B8', font: { family: 'Inter', size: 11 } }
          },
          tooltip: {
            backgroundColor: '#0E1524',
            titleColor: '#00F0FF',
            bodyColor: '#F3F4F6',
            borderColor: '#1E2D4A',
            borderWidth: 1
          }
        },
        scales: {
          x: {
            grid: { color: 'rgba(255,255,255,0.04)' },
            ticks: { color: '#64748B', font: { size: 10 } }
          },
          y: {
            grid: { color: 'rgba(255,255,255,0.04)' },
            ticks: { color: '#64748B', font: { size: 10 } }
          }
        }
      }
    });
  }

  initBreakdownChart(canvasId, breakdown = {}) {
    const ctx = document.getElementById(canvasId);
    if (!ctx || !window.Chart) return;

    if (this.breakdownChart) {
      this.breakdownChart.destroy();
    }

    const labels = Object.keys(breakdown);
    const data = Object.values(breakdown);
    const colors = ['#EF4444', '#F59E0B', '#8B5CF6', '#3B82F6', '#EC4899'];

    this.breakdownChart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: labels.length > 0 ? labels : ['No Failures'],
        datasets: [{
          data: data.length > 0 ? data : [1],
          backgroundColor: data.length > 0 ? colors.slice(0, labels.length) : ['#1E2D4A'],
          borderColor: '#131D31',
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '70%',
        plugins: {
          legend: {
            position: 'right',
            labels: { color: '#94A3B8', font: { size: 11 } }
          }
        }
      }
    });
  }

  initSlaBarChart(canvasId, steps = []) {
    const ctx = document.getElementById(canvasId);
    if (!ctx || !window.Chart) return;

    if (this.slaChart) {
      this.slaChart.destroy();
    }

    const labels = steps.map(s => s.step_name);
    const observed = steps.map(s => s.latency_ms);
    const slaLimits = [400, 500, 800, 1200, 1500, 1000];

    this.slaChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [
          {
            label: 'Observed Latency (ms)',
            data: observed,
            backgroundColor: observed.map((v, i) => v > (slaLimits[i] || 1200) ? '#EF4444' : '#00F0FF'),
            borderRadius: 4
          },
          {
            label: 'SLA Limit (ms)',
            data: slaLimits.slice(0, labels.length),
            backgroundColor: 'rgba(148, 163, 184, 0.2)',
            borderRadius: 4
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { labels: { color: '#94A3B8', font: { size: 11 } } }
        },
        scales: {
          x: { ticks: { color: '#64748B' }, grid: { display: false } },
          y: { ticks: { color: '#64748B' }, grid: { color: 'rgba(255,255,255,0.04)' } }
        }
      }
    });
  }
}

window.flowSentryCharts = new FlowSentryCharts();
