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

    this.charts.jit = new Chart(document.getElementById('c-jit'), {
      type: 'line', options: commonOpts,
      data: { labels: [], datasets: [
        this._ds('outstanding (MB)', '#a05ed9'),
        this._ds('churn',            '#ff7878'),
      ]}
    });

    this.charts.process = new Chart(document.getElementById('c-process'), {
      type: 'line', options: commonOpts,
      data: { labels: [], datasets: [
        this._ds('fork',  '#5b9cf2'),
        this._ds('vfork', '#7ed957'),
        this._ds('exec',  '#f29c5b'),
        this._ds('clone', '#a05ed9'),
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
    this._push(this.charts.jit, [
      jitMB,
      KState.rate(snap, prev, 'jit.churn'),
    ]);

    this._push(this.charts.process, [
      snap.process ? snap.process.fork : 0,
      snap.process ? snap.process.vfork : 0,
      snap.process ? snap.process.exec : 0,
      snap.threads ? snap.threads.clone_entry : 0,
    ]);

    this._push(this.charts.prot, [
      KState.rate(snap, prev, 'protection.protectDB_calls'),
      KState.rate(snap, prev, 'protection.unprotectDB_calls'),
      KState.rate(snap, prev, 'protection.setProtection_calls'),
    ]);
  }
};
