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
        this._ds('malloc/s',     '#5b9cf2'),
        this._ds('free/s',       '#f29c5b'),
        this._ds('calloc/s',     '#5bd9e0'),
        this._ds('realloc/s',    '#e85bd9'),
        this._ds('jit alloc/s',  '#7ed957'),
        this._ds('jit free/s',   '#d97e5e'),
      ]}
    });

    /* JIT chart: one line per process showing live JIT block COUNT
     * over time (live = jit_count - jit_freed_count). Datasets are
     * built dynamically as PIDs appear — see _updateJitPerPid below.
     * Initial datasets array is empty. */
    this.charts.jit = new Chart(document.getElementById('c-jit'), {
      type: 'line', options: commonOpts,
      data: { labels: [], datasets: [] }
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

  /* Stable per-PID color: same PID always gets the same color across
   * snapshot updates. Palette length is coprime-ish with typical PID
   * spacings to reduce immediate-neighbor collisions. */
  _PID_PALETTE: ['#5b9cf2', '#f29c5b', '#7ed957', '#a05ed9', '#5bd9e0',
                 '#e85bd9', '#d97e5e', '#5be08c', '#e0c45b', '#5b6ee0',
                 '#e05b6e'],

  _pidColor: function(pid) {
    return this._PID_PALETTE[(pid >>> 0) % this._PID_PALETTE.length];
  },

  /* Multi-line JIT chart: one dataset per PID, value = live JIT block
   * count (jit_count − jit_freed_count). Each snapshot:
   *   - Existing datasets get the new value or null (PID went idle /
   *     dropped from the top-32 truncation in _per_pid_snapshot).
   *   - Newly-seen PIDs get a fresh dataset, backfilled with nulls so
   *     the line starts at the current x-axis position rather than 0.
   *   - When dataset count exceeds the cap, the lowest-current-value
   *     ones are dropped to keep the legend readable.
   */
  _JIT_DATASET_CAP: 10,

  _updateJitPerPid: function(snap) {
    var chart = this.charts.jit;
    if (!chart) return;
    var pids = (snap && snap.pids) || [];

    /* Build pid -> {live, label} for this snapshot. Drop PIDs whose
     * live count is 0 — they'd add a flat-zero line that just clutters
     * the legend. */
    var pidLive = {};
    for (var i = 0; i < pids.length; i++) {
      var p = pids[i];
      var live = (p.jit_count || 0) - (p.jit_freed_count || 0);
      if (live > 0) {
        pidLive[p.pid] = {live: live, label: p.label || ''};
      }
    }

    /* Push the new x-axis label. */
    var t = new Date().toLocaleTimeString();
    chart.data.labels.push(t);
    if (chart.data.labels.length > 120) chart.data.labels.shift();

    /* Update existing datasets — each gets either the current PID's
     * live count, or null for line gap. Mark consumed entries so the
     * next loop only touches genuinely-new PIDs. */
    for (i = 0; i < chart.data.datasets.length; i++) {
      var ds = chart.data.datasets[i];
      var entry = pidLive[ds.pidId];
      ds.data.push(entry ? entry.live : null);
      if (ds.data.length > 120) ds.data.shift();
      if (entry) delete pidLive[ds.pidId];
    }

    /* Add datasets for PIDs we haven't seen before. Backfill data
     * with nulls so existing labels' length matches. */
    var newPids = Object.keys(pidLive);
    /* Most-active first so the legend ordering is meaningful when
     * many PIDs appear in the same snapshot. */
    newPids.sort(function(a, b) { return pidLive[b].live - pidLive[a].live; });
    var historyLen = chart.data.labels.length;
    for (i = 0; i < newPids.length; i++) {
      var newPid = newPids[i];
      var newEntry = pidLive[newPid];
      var label = newPid + (newEntry.label ? ' ' + newEntry.label : '');
      var fresh = this._ds(label, this._pidColor(newPid));
      fresh.pidId = parseInt(newPid, 10);
      var pad = new Array(historyLen - 1);
      for (var k = 0; k < pad.length; k++) pad[k] = null;
      pad.push(newEntry.live);
      fresh.data = pad;
      chart.data.datasets.push(fresh);
    }

    /* Cap dataset count. When too many lines pile up, drop the ones
     * with the lowest most-recent live count (the leaders stay
     * visible). */
    if (chart.data.datasets.length > this._JIT_DATASET_CAP) {
      chart.data.datasets.sort(function(a, b) {
        var av = a.data[a.data.length - 1] || 0;
        var bv = b.data[b.data.length - 1] || 0;
        return bv - av;
      });
      chart.data.datasets.length = this._JIT_DATASET_CAP;
    }

    chart.update('none');
  },

  update: function(snap, prev) {
    if (!this.charts.alloc) return;

    this._push(this.charts.alloc, [
      KState.rate(snap, prev, 'alloc.malloc'),
      KState.rate(snap, prev, 'alloc.free'),
      KState.rate(snap, prev, 'alloc.calloc'),
      KState.rate(snap, prev, 'alloc.realloc'),
      KState.rate(snap, prev, 'jit.alloc_count'),
      KState.rate(snap, prev, 'jit.free_count'),
    ]);

    this._updateJitPerPid(snap);

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
