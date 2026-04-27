/* SVG arc gauges for the overview bar.
 * drawArc lifted verbatim from kbox/web/js/gauges.js (MIT, NCKU 2026).
 * update() rewired to box64_trace metrics. */
'use strict';

var KGauges = {
  drawArc: function(id, pct) {
    var el = document.getElementById(id);
    if (!el) return;
    pct = Math.max(0, Math.min(1, pct));
    var r = 30, cx = 40, cy = 38;
    var startAngle = Math.PI;
    var endAngle = Math.PI - (pct * Math.PI);
    var x1 = cx + r * Math.cos(startAngle);
    var y1 = cy + r * Math.sin(startAngle);
    var x2 = cx + r * Math.cos(endAngle);
    var y2 = cy + r * Math.sin(endAngle);
    var large = pct > 0.5 ? 1 : 0;
    if (pct <= 0) {
      el.setAttribute('d', '');
      return;
    }
    el.setAttribute('d',
      'M ' + x1 + ' ' + y1 +
      ' A ' + r + ' ' + r + ' 0 ' + large + ' 0 ' + x2 + ' ' + y2);
  },

  fmtNum: function(n) {
    if (n < 1000) return Math.round(n);
    if (n < 1000000) return (n/1000).toFixed(1) + 'k';
    return (n/1000000).toFixed(1) + 'M';
  },

  fmtBytes: function(n) {
    if (n < 1024) return n + 'B';
    if (n < 1024*1024) return (n/1024).toFixed(1) + 'K';
    if (n < 1024*1024*1024) return (n/(1024*1024)).toFixed(1) + 'M';
    return (n/(1024*1024*1024)).toFixed(2) + 'G';
  },

  /* Apply level class to gauge wrapper for anomaly coloring */
  setLevel: function(elId, val, warn, danger) {
    var el = document.getElementById(elId);
    if (!el) return;
    el.classList.remove('warn', 'danger');
    if (val >= danger) el.classList.add('danger');
    else if (val >= warn) el.classList.add('warn');
  },

  renderPidTable: function(pids) {
    var tbody = document.getElementById('pid-tbody');
    if (!tbody || !pids) return;
    /* Diff-friendly: rebuild only if row count changes; otherwise update cells.
     * Simpler v1: full re-render. */
    var rows = '';
    for (var i = 0; i < pids.length; i++) {
      var p = pids[i];
      var label = p.label ? p.label : '';
      /* Truncate long labels */
      if (label.length > 32) label = label.substr(0, 29) + '...';
      var dangerCls = p.jit_bytes > 1024*1024*1024 ? ' class="row-danger"' :
                      (p.jit_bytes > 256*1024*1024 ? ' class="row-warn"' : '');
      rows += '<tr' + dangerCls + '>' +
              '<td>' + p.pid + '</td>' +
              '<td>' + label + '</td>' +
              '<td class="num">' + p.threads_alive + '</td>' +
              '<td class="num">' + this.fmtBytes(p.jit_bytes) + '</td>' +
              '<td class="num">' + this.fmtNum(p.jit_count) + '</td>' +
              '<td class="num">' + this.fmtBytes(p.malloc_bytes) + '</td>' +
              '<td class="num">' + this.fmtBytes(p.mmap_bytes) + '</td>' +
              '<td class="num">' + p.context_created + '</td>' +
              '</tr>';
    }
    tbody.innerHTML = rows || '<tr><td colspan="8" class="empty">no box64 processes seen yet</td></tr>';
  },

  update: function(snap, prev) {
    /* Allocator rate (malloc + calloc + realloc + JIT alloc per second) */
    var allocRate = KState.rate(snap, prev, 'alloc.malloc') +
                    KState.rate(snap, prev, 'alloc.calloc') +
                    KState.rate(snap, prev, 'alloc.realloc') +
                    KState.rate(snap, prev, 'jit.alloc_count');
    document.getElementById('g-allocs-val').textContent = this.fmtNum(allocRate);
    this.drawArc('g-allocs-arc', Math.min(allocRate / 5000, 1));
    this.setLevel('g-allocs', allocRate, 5000, 20000);

    /* Outstanding JIT MB */
    var jitMB = (snap.jit && snap.jit.outstanding_bytes) ?
                snap.jit.outstanding_bytes / (1024 * 1024) : 0;
    document.getElementById('g-jit-val').textContent =
      jitMB < 1000 ? jitMB.toFixed(1) : (jitMB/1000).toFixed(2) + 'G';
    this.drawArc('g-jit-arc', Math.min(jitMB / 200, 1));
    this.setLevel('g-jit', jitMB, 256, 1024);   /* warn 256 MB, danger 1 GB */

    /* Forks (cumulative — gauge fills as box64 spawns processes) */
    var forks = snap.process ? snap.process.fork + snap.process.vfork : 0;
    document.getElementById('g-fork-val').textContent = forks;
    this.drawArc('g-fork-arc', Math.min(forks / 50, 1));
    this.setLevel('g-fork', forks, 50, 200);

    /* Threads alive (create_return - destroy_entry) */
    var threadsAlive = 0;
    if (snap.threads) {
      threadsAlive = Math.max(0, (snap.threads.create_return || 0) -
                                  (snap.threads.destroy_entry || 0));
    }
    document.getElementById('g-threads-val').textContent = threadsAlive;
    this.drawArc('g-threads-arc', Math.min(threadsAlive / 64, 1));
    this.setLevel('g-threads', threadsAlive, 64, 256);

    /* Per-PID table */
    if (snap.pids) this.renderPidTable(snap.pids);

    /* Bottom-line stats */
    if (snap.alloc) {
      document.getElementById('s-malloc').textContent = snap.alloc.malloc;
      document.getElementById('s-free').textContent = snap.alloc.free;
      document.getElementById('s-bytes').textContent = this.fmtNum(snap.alloc.bytes_allocated);
    }
    if (snap.jit) {
      document.getElementById('s-jit-alloc').textContent = snap.jit.alloc_count;
      document.getElementById('s-jit-free').textContent = snap.jit.free_count;
      document.getElementById('s-jit-out').textContent = snap.jit.outstanding_blocks;
    }
    if (snap.process) {
      document.getElementById('s-fork').textContent = snap.process.fork;
      document.getElementById('s-vfork').textContent = snap.process.vfork;
      document.getElementById('s-exec').textContent = snap.process.exec;
    }

    /* Cache-policy panels */
    if (snap.histograms) {
      this.renderHist('hist-alloc-sizes',
        snap.histograms.alloc_sizes, this._fmtSizeRange);
      this.renderHist('hist-block-lifetimes',
        snap.histograms.block_lifetimes, this._fmtNsRange);
    }
    if (snap.top_churned) this.renderChurnTable(snap.top_churned);
    if (snap.top_blocks) this.renderTopBlocks(snap.top_blocks);
    if (snap.jit) {
      var inv = document.getElementById('s-invalid');
      var mark = document.getElementById('s-mark');
      var ch = document.getElementById('s-churn-total');
      if (inv) inv.textContent = snap.jit.invalidations;
      if (mark) mark.textContent = snap.jit.dirty_marks;
      if (ch) ch.textContent = snap.jit.churn;
    }
  },

  /* Format a log2 bucket [2^k, 2^(k+1)) as a human-readable byte range. */
  _fmtSizeRange: function(b) {
    var lo = b === 0 ? 0 : Math.pow(2, b);
    var hi = Math.pow(2, b + 1) - 1;
    return KGauges.fmtBytes(lo) + '-' + KGauges.fmtBytes(hi);
  },

  /* Format a log2 bucket as a human-readable nanosecond range. */
  _fmtNsRange: function(b) {
    var fmt = function(ns) {
      if (ns < 1000) return ns + 'ns';
      if (ns < 1e6) return (ns/1000).toFixed(0) + 'us';
      if (ns < 1e9) return (ns/1e6).toFixed(0) + 'ms';
      return (ns/1e9).toFixed(1) + 's';
    };
    var lo = b === 0 ? 0 : Math.pow(2, b);
    var hi = Math.pow(2, b + 1) - 1;
    return fmt(lo) + '-' + fmt(hi);
  },

  /* Render a log2 histogram as horizontal CSS bars. */
  renderHist: function(elId, buckets, fmtRange) {
    var el = document.getElementById(elId);
    if (!el) return;
    if (!buckets || !buckets.length) {
      el.innerHTML = '<div class="hist-empty">(no samples yet)</div>';
      return;
    }
    var max = 0;
    for (var i = 0; i < buckets.length; i++) {
      if (buckets[i].count > max) max = buckets[i].count;
    }
    if (max <= 0) max = 1;
    var html = '';
    for (i = 0; i < buckets.length; i++) {
      var b = buckets[i];
      var pct = Math.round(100 * b.count / max);
      html += '<div class="hist-row">' +
              '<div class="hist-label">' + fmtRange(b.bucket) + '</div>' +
              '<div class="hist-bar-wrap">' +
              '<div class="hist-bar" style="width:' + pct + '%"></div>' +
              '</div>' +
              '<div class="hist-count">' + this.fmtNum(b.count) + '</div>' +
              '</div>';
    }
    el.innerHTML = html;
  },

  renderChurnTable: function(rows) {
    var tbody = document.getElementById('churn-tbody');
    if (!tbody) return;
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="2" class="empty">(no churn yet)</td></tr>';
      return;
    }
    var html = '';
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i];
      var addr = '0x' + r.x64_addr.toString(16).padStart(8, '0');
      html += '<tr><td><code>' + addr + '</code></td>' +
              '<td class="num">' + r.count + '</td></tr>';
    }
    tbody.innerHTML = html;
  },

  renderTopBlocks: function(rows) {
    var tbody = document.getElementById('top-blocks-tbody');
    if (!tbody) return;
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="empty">(no live blocks)</td></tr>';
      return;
    }
    var html = '';
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i];
      var x64 = '0x' + r.x64_addr.toString(16).padStart(8, '0');
      var ah = '0x' + r.alloc_addr.toString(16).padStart(8, '0');
      html += '<tr><td><code>' + x64 + '</code></td>' +
              '<td><code>' + ah + '</code></td>' +
              '<td class="num">' + this.fmtBytes(r.size) + '</td>' +
              '<td class="num">' + r.pid + '</td></tr>';
    }
    tbody.innerHTML = html;
  }
};
