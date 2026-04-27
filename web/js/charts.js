/* Chart.js time-series charts for box64_trace metrics. */
'use strict';

var KCharts = {
  charts: {},

  _commonOpts: function() {
    return {
      animation: false,
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { display: false },
        y: { beginAtZero: true, ticks: { font: { size: 10 } } }
      },
      plugins: { legend: { display: true, position: 'bottom',
                           labels: { boxWidth: 10, font: { size: 11 } } } }
    };
  },

  _ds: function(label, color) {
    return { label: label, data: [], borderColor: color, backgroundColor: color,
             borderWidth: 1.5, pointRadius: 0, tension: 0.2, fill: false };
  },

  init: function() {
    var commonOpts = this._commonOpts();
    var commonStacked = JSON.parse(JSON.stringify(commonOpts));

    this.charts.alloc = new Chart(document.getElementById('c-alloc'), {
      type: 'line', options: commonOpts,
      data: { labels: [], datasets: [
        this._ds('malloc/s', '#5b9cf2'),
        this._ds('free/s',   '#f29c5b'),
        this._ds('jit alloc/s', '#7ed957'),
      ]}
    });

    /* JIT chart: outstanding MB only (single scale).  Churn is rare and
     * gets crushed near zero on a shared axis; surface it via the gauges
     * + table instead. */
    this.charts.jit = new Chart(document.getElementById('c-jit'), {
      type: 'line', options: commonOpts,
      data: { labels: [], datasets: [
        this._ds('outstanding (MB)', '#a05ed9'),
      ]}
    });

    /* Process chart: per-interval rates (not cumulative totals).  Cumulative
     * counts only ever grow, which makes the chart useless for spotting
     * bursts. */
    this.charts.process = new Chart(document.getElementById('c-process'), {
      type: 'line', options: commonOpts,
      data: { labels: [], datasets: [
        this._ds('fork/s',  '#5b9cf2'),
        this._ds('vfork/s', '#7ed957'),
        this._ds('exec/s',  '#f29c5b'),
        this._ds('clone/s', '#a05ed9'),
      ]}
    });

    this.charts.prot = new Chart(document.getElementById('c-prot'), {
      type: 'line', options: commonOpts,
      data: { labels: [], datasets: [
        this._ds('protectDB/s',     '#5b9cf2'),
        this._ds('unprotectDB/s',   '#7ed957'),
        this._ds('setProtection/s', '#f29c5b'),
      ]}
    });
  },

  _push: function(chart, values) {
    var t = new Date().toLocaleTimeString();
    chart.data.labels.push(t);
    if (chart.data.labels.length > 120) chart.data.labels.shift();
    for (var i = 0; i < values.length; i++) {
      chart.data.datasets[i].data.push(values[i]);
      if (chart.data.datasets[i].data.length > 120)
        chart.data.datasets[i].data.shift();
    }
    chart.update('none');
  },

  update: function(snap, prev) {
    if (!this.charts.alloc) return;

    this._push(this.charts.alloc, [
      KState.rate(snap, prev, 'alloc.malloc'),
      KState.rate(snap, prev, 'alloc.free'),
      KState.rate(snap, prev, 'jit.alloc_count'),
    ]);

    var jitMB = (snap.jit && snap.jit.outstanding_bytes) ?
                snap.jit.outstanding_bytes / (1024 * 1024) : 0;
    this._push(this.charts.jit, [jitMB]);

    this._push(this.charts.process, [
      KState.rate(snap, prev, 'process.fork'),
      KState.rate(snap, prev, 'process.vfork'),
      KState.rate(snap, prev, 'process.exec'),
      KState.rate(snap, prev, 'threads.clone_entry'),
    ]);

    this._push(this.charts.prot, [
      KState.rate(snap, prev, 'protection.protectDB_calls'),
      KState.rate(snap, prev, 'protection.unprotectDB_calls'),
      KState.rate(snap, prev, 'protection.setProtection_calls'),
    ]);
  }
};
