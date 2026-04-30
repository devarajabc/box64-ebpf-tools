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
      /* Live blocks = alloc - freed (JIT). Older snapshots before the
       * jit_freed_count field landed will leave it undefined; fall back
       * to "—" instead of NaN. */
      var liveCell, invCell, invPctCell;
      if (typeof p.jit_freed_count === 'number') {
        var live = p.jit_count - p.jit_freed_count;
        liveCell = this.fmtNum(live);
      } else {
        liveCell = '—';
      }
      if (typeof p.jit_invalidations === 'number') {
        invCell = this.fmtNum(p.jit_invalidations);
        var pct = p.jit_count > 0 ? (p.jit_invalidations / p.jit_count * 100) : 0;
        invPctCell = pct.toFixed(1) + '%';
      } else {
        invCell = '—';
        invPctCell = '—';
      }
      rows += '<tr' + dangerCls + '>' +
              '<td>' + p.pid + '</td>' +
              '<td>' + label + '</td>' +
              '<td class="num">' + p.threads_alive + '</td>' +
              '<td class="num">' + this.fmtBytes(p.jit_bytes) + '</td>' +
              '<td class="num">' + this.fmtNum(p.jit_count) + '</td>' +
              '<td class="num">' + liveCell + '</td>' +
              '<td class="num">' + invCell + '</td>' +
              '<td class="num">' + invPctCell + '</td>' +
              '<td class="num">' + this.fmtBytes(p.malloc_bytes) + '</td>' +
              '<td class="num">' + this.fmtBytes(p.mmap_bytes) + '</td>' +
              '<td class="num">' + p.context_created + '</td>' +
              '</tr>';
    }
    tbody.innerHTML = rows || '<tr><td colspan="11" class="empty">no box64 processes seen yet</td></tr>';
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
      document.getElementById('s-bytes').textContent = this.fmtBytes(snap.alloc.bytes_allocated);
      var freed = snap.alloc.bytes_freed || 0;
      var net = (snap.alloc.bytes_allocated || 0) - freed;
      var freedEl = document.getElementById('s-bytes-freed');
      var netEl = document.getElementById('s-bytes-net');
      if (freedEl) freedEl.textContent = this.fmtBytes(freed);
      if (netEl) {
        /* Net is signed — fmtBytes only handles non-negative. Render the
         * sign separately so a negative net (over-free, unusual) is
         * obvious without breaking the formatter. */
        netEl.textContent = (net < 0 ? '-' : '') + this.fmtBytes(Math.abs(net));
      }
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
      var spawnEl = document.getElementById('s-spawn');
      var pvEl = document.getElementById('s-pv');
      var ctxNewEl = document.getElementById('s-ctx-new');
      var ctxFreeEl = document.getElementById('s-ctx-free');
      if (spawnEl) spawnEl.textContent = snap.process.posix_spawn || 0;
      if (pvEl) pvEl.textContent = snap.process.pressure_vessel || 0;
      if (ctxNewEl) ctxNewEl.textContent = snap.process.new_context || 0;
      if (ctxFreeEl) ctxFreeEl.textContent = snap.process.free_context || 0;
    }
    if (snap.mmap) {
      var mmiEl = document.getElementById('s-mmap-internal');
      var muiEl = document.getElementById('s-munmap-internal');
      var mbEl  = document.getElementById('s-mmap-box');
      var mubEl = document.getElementById('s-munmap-box');
      if (mmiEl) mmiEl.textContent = this.fmtNum(snap.mmap.internal_mmap || 0);
      if (muiEl) muiEl.textContent = this.fmtNum(snap.mmap.internal_munmap || 0);
      if (mbEl)  mbEl.textContent  = this.fmtNum(snap.mmap.box_mmap || 0);
      if (mubEl) mubEl.textContent = this.fmtNum(snap.mmap.box_munmap || 0);
    }

    /* Allocator tier breakdown + extras — aggregated across pids[] since
     * proc_mem_t carries the per-PID counters. The LIST tier is derived
     * (total customMalloc-family calls minus slab tiers). All KPIs render
     * as percentages where the denominator is the sum of customMalloc
     * calls, so an empty-state run shows 0% / 0% / 0% rather than NaN. */
    if (snap.pids) {
      var tier64 = 0, tier128 = 0, totalAlloc = 0;
      var aligned = 0, stray = 0, grow = 0;
      for (var pi = 0; pi < snap.pids.length; pi++) {
        var pp = snap.pids[pi];
        tier64     += pp.tier64_count     || 0;
        tier128    += pp.tier128_count    || 0;
        aligned    += pp.aligned_count    || 0;
        stray      += pp.stray_free_count || 0;
        grow       += pp.slab_grow_count  || 0;
        /* total customMalloc-family = malloc + calloc + realloc; rows
         * carry the call counts (malloc_count / free_count exist; for
         * tier % we derive total from the snapshot's aggregate alloc
         * bucket where available). */
      }
      if (snap.alloc) {
        totalAlloc = (snap.alloc.malloc || 0) + (snap.alloc.calloc || 0)
                   + (snap.alloc.realloc || 0);
      }
      var listTier = Math.max(0, totalAlloc - tier64 - tier128);
      var fmtPct = function(n, t) {
        return t > 0 ? (n / t * 100).toFixed(1) + '%' : '0.0%';
      };
      var t64 = document.getElementById('s-tier64');
      var t128 = document.getElementById('s-tier128');
      var tList = document.getElementById('s-tier-list');
      if (t64)  t64.textContent  = fmtPct(tier64, totalAlloc);
      if (t128) t128.textContent = fmtPct(tier128, totalAlloc);
      if (tList) tList.textContent = fmtPct(listTier, totalAlloc);
      var ae = document.getElementById('s-aligned-count');
      var se = document.getElementById('s-stray-free');
      var ge = document.getElementById('s-slab-grow');
      if (ae) ae.textContent = this.fmtNum(aligned);
      if (se) se.textContent = this.fmtNum(stray);
      if (ge) ge.textContent = this.fmtNum(grow);
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
