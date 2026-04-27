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

  update: function(snap, prev) {
    /* Allocator rate (malloc + calloc + realloc + JIT alloc per second) */
    var allocRate = KState.rate(snap, prev, 'alloc.malloc') +
                    KState.rate(snap, prev, 'alloc.calloc') +
                    KState.rate(snap, prev, 'alloc.realloc') +
                    KState.rate(snap, prev, 'jit.alloc_count');
    document.getElementById('g-allocs-val').textContent = this.fmtNum(allocRate);
    this.drawArc('g-allocs-arc', Math.min(allocRate / 5000, 1));

    /* Outstanding JIT MB */
    var jitMB = (snap.jit && snap.jit.outstanding_bytes) ?
                snap.jit.outstanding_bytes / (1024 * 1024) : 0;
    document.getElementById('g-jit-val').textContent =
      jitMB < 1000 ? jitMB.toFixed(1) : (jitMB/1000).toFixed(2) + 'G';
    this.drawArc('g-jit-arc', Math.min(jitMB / 200, 1));

    /* Forks (cumulative — gauge fills as box64 spawns processes) */
    var forks = snap.process ? snap.process.fork + snap.process.vfork : 0;
    document.getElementById('g-fork-val').textContent = forks;
    this.drawArc('g-fork-arc', Math.min(forks / 50, 1));

    /* Threads alive (create_return - destroy_entry) */
    var threadsAlive = 0;
    if (snap.threads) {
      threadsAlive = Math.max(0, (snap.threads.create_return || 0) -
                                  (snap.threads.destroy_entry || 0));
    }
    document.getElementById('g-threads-val').textContent = threadsAlive;
    this.drawArc('g-threads-arc', Math.min(threadsAlive / 64, 1));

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
  }
};
