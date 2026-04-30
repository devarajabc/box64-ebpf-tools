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
    /* Allocator rate: customMalloc + customCalloc + customRealloc +
     * customMemAligned + AllocDynarecMap, all per second. The aligned
     * cumulative count lives at tier_totals.aligned_count (no separate
     * top-level alloc.aligned field). Without this term the gauge
     * undercounted real allocation activity on workloads that hit
     * posix_memalign / aligned_alloc paths. */
    var allocRate = KState.rate(snap, prev, 'alloc.malloc') +
                    KState.rate(snap, prev, 'alloc.calloc') +
                    KState.rate(snap, prev, 'alloc.realloc') +
                    KState.rate(snap, prev, 'tier_totals.aligned_count') +
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

    /* Allocator tier breakdown + extras — read from snap.tier_totals,
     * which the backend computes against the FULL proc_mem map.
     * Summing over snap.pids[] would skew on hosts with >32 box64 PIDs
     * (pids[] is capped at 32 to keep payload size bounded). Falls back
     * to "—" if tier_totals is absent (older backend during a rolling
     * refresh). */
    var tt = snap.tier_totals;
    if (tt) {
      /* Show real counts AND percentage so the user can spot a 1k-vs-100k
       * difference that would look identical at "100% slab 64B". The KPI
       * cell is one line, so we render "{count} ({pct}%)". fmtNum
       * abbreviates >1k → "1.5k", >1M → "1.5M" so it stays narrow. */
      var fmtCountPct = function(n, p) {
        return KGauges.fmtNum(n) + ' (' + p.toFixed(1) + '%)';
      };
      var t64 = document.getElementById('s-tier64');
      var t128 = document.getElementById('s-tier128');
      var tList = document.getElementById('s-tier-list');
      if (t64)   t64.textContent   = fmtCountPct(tt.tier64  || 0, tt.tier64_pct  || 0);
      if (t128)  t128.textContent  = fmtCountPct(tt.tier128 || 0, tt.tier128_pct || 0);
      if (tList) tList.textContent = fmtCountPct(tt.list    || 0, tt.list_pct    || 0);
      var ae = document.getElementById('s-aligned-count');
      var se = document.getElementById('s-stray-free');
      var ge = document.getElementById('s-slab-grow');
      if (ae) ae.textContent = this.fmtNum(tt.aligned_count || 0);
      if (se) se.textContent = this.fmtNum(tt.stray_free    || 0);
      if (ge) ge.textContent = this.fmtNum(tt.slab_grow     || 0);
    }

    /* JIT-side dynablock-extras (Bundle A: pressure + Bundle B: range
     * invalidation). Read from snap.jit_pressure — aggregated by the
     * backend across the FULL proc_mem map, threads excluded. Falls
     * back to "0" if the snapshot is from an older backend during a
     * rolling refresh (no fields ⇒ all zeros, not NaN). */
    var jp = snap.jit_pressure;
    if (jp) {
      var pe = document.getElementById('s-jit-purge');
      var ce = document.getElementById('s-jit-cancel');
      var bge = document.getElementById('s-box32-grow');
      if (pe)  pe.textContent  = this.fmtNum(jp.jit_purge      || 0);
      if (ce)  ce.textContent  = this.fmtNum(jp.jit_cancel     || 0);
      if (bge) bge.textContent = this.fmtNum(jp.box32_grow     || 0);
      var ri = document.getElementById('s-range-inval');
      var rf = document.getElementById('s-range-free');
      var dse = document.getElementById('s-dbswap');
      if (ri)  ri.textContent  = this.fmtNum(jp.range_inval    || 0);
      if (rf)  rf.textContent  = this.fmtNum(jp.range_free     || 0);
      if (dse) dse.textContent = this.fmtNum(jp.dbswap_invalid || 0);
      /* Purge ratio = purge / jit_alloc * 100. Computed in JS from
       * existing fields (no backend change). Renders "—" when there
       * are no allocations yet, so a fresh attach doesn't show "0%"
       * (which could be confused with a healthy steady-state). */
      var pr = document.getElementById('s-purge-ratio');
      if (pr) {
        var allocs = (snap.jit && snap.jit.alloc_count) || 0;
        if (allocs > 0) {
          pr.textContent = ((jp.jit_purge || 0) / allocs * 100).toFixed(2) + '%';
        } else {
          pr.textContent = '—';
        }
      }
    }

    /* Live JIT Block Age histogram. Backend computes age = now - alloc_ns
     * and bucketizes via floor(log2). Reuse the existing renderHist +
     * _fmtNsRange so labels display "1ms-2ms", "32ms-63ms", etc. */
    if (snap.histograms && snap.histograms.block_ages) {
      this.renderHist('hist-block-ages',
        snap.histograms.block_ages, this._fmtNsRange);
    }

    /* JIT Blocks per process — answers "which PID is sitting on the
     * JIT cache?". Live = jit_count − jit_freed_count, top 5 sorted
     * desc. Reuses the .hist-* CSS so it visually rhymes with the
     * size/lifetime histograms below. */
    if (snap.pids) this.renderJitPidBlocks(snap.pids);

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

  renderJitPidBlocks: function(pids) {
    var el = document.getElementById('jit-pid-blocks');
    if (!el) return;
    /* Compute live = jit_count - jit_freed_count for each PID; drop
     * rows with zero live blocks (forks that inherited but did no
     * JIT work, idle threads, etc.) so the panel stays compact. */
    var rows = [];
    for (var i = 0; i < pids.length; i++) {
      var p = pids[i];
      var live = (p.jit_count || 0) - (p.jit_freed_count || 0);
      if (live > 0) {
        rows.push({pid: p.pid, label: p.label || '', live: live});
      }
    }
    if (!rows.length) {
      el.innerHTML = '<div class="hist-empty">(no live JIT blocks)</div>';
      return;
    }
    rows.sort(function(a, b) { return b.live - a.live; });
    rows = rows.slice(0, 5);   /* top 5 — keeps the panel from growing */
    var max = rows[0].live;
    var html = '';
    for (i = 0; i < rows.length; i++) {
      var r = rows[i];
      var lab = r.label.length > 24 ? r.label.substr(0, 21) + '...' : r.label;
      /* "PID label" as one short string fits the .hist-label slot
       * (which the CSS keeps narrow); count in the right cell. */
      var cell = String(r.pid) + (lab ? ' ' + lab : '');
      var pct = Math.round(100 * r.live / max);
      html += '<div class="hist-row">' +
              '<div class="hist-label">' + cell + '</div>' +
              '<div class="hist-bar-wrap">' +
              '<div class="hist-bar" style="width:' + pct + '%"></div>' +
              '</div>' +
              '<div class="hist-count">' + this.fmtNum(r.live) + '</div>' +
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
