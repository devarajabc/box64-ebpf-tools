/* Snapshot polling and SSE connection management */
'use strict';

var KPolling = {
  timer: null,
  evtSource: null,
  historyLoaded: false,

  start: function() {
    var self = this;
    /* Load history first, then start polling to avoid prevSnap races */
    var startPolling = function() {
      self.poll();
      self.timer = setInterval(self.poll.bind(self), KState.pollInterval);
    };
    this.loadHistory().then(startPolling, startPolling);
    this.connectSSE();
  },

  stop: function() {
    if (this.timer) clearInterval(this.timer);
    if (this.evtSource) this.evtSource.close();
  },

  /* Fetch historical snapshots on initial load to backfill charts */
  loadHistory: function() {
    return fetch('/api/history')
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (!data.snapshots || !data.snapshots.length) return;
        var snaps = data.snapshots;
        for (var i = 0; i < snaps.length; i++) {
          KState.pushSnap(snaps[i]);
          if (i > 0) KCharts.update(snaps[i], snaps[i - 1]);
        }
        KState.prevSnap = snaps[snaps.length - 1];
        /* Seed glow levels from last two history snapshots */
        if (snaps.length >= 2)
          KTelemetry.onSnapshot(snaps[snaps.length - 1], snaps[snaps.length - 2]);
        KPolling.historyLoaded = true;
      })
      .catch(function() {});
  },

  poll: function() {
    if (KState.paused) return;
    fetch('/api/snapshot')
      .then(function(r) { return r.json(); })
      .then(function(snap) {
        var prev = KState.prevSnap;
        KState.pushSnap(snap);
        KState.prevSnap = snap;

        KGauges.update(snap, prev);
        KCharts.update(snap, prev);
        KTelemetry.onSnapshot(snap, prev);
        KState.connected = true;
        KPolling.failCount = 0;
        KPolling.setOffline(false);
      })
      .catch(function() {
        KState.connected = false;
        KPolling.failCount = (KPolling.failCount || 0) + 1;
        if (KPolling.failCount >= 2) KPolling.setOffline(true);
      });

    /* Guest name changes rarely; fetch in parallel, not chained */
    fetch('/stats')
      .then(function(r) { return r.json(); })
      .then(function(s) {
        if (s.guest) document.getElementById('guest').textContent = s.guest;
      })
      .catch(function() {});
  },

  connectSSE: function() {
    if (this.evtSource) this.evtSource.close();

    this.evtSource = new EventSource('/api/events');
    this.evtSource.addEventListener('syscall', function(e) {
      try {
        var d = JSON.parse(e.data);
        KEvents.addEvent('syscall', d);
        KTelemetry.onSyscallEvent(d);
      } catch(err) {}
    });
    this.evtSource.addEventListener('process', function(e) {
      try {
        var d = JSON.parse(e.data);
        KEvents.addEvent('process', d);
      } catch(err) {}
    });
    this.evtSource.onopen = function() {
      KState.connected = true;
      KPolling.setOffline(false);
    };
    this.evtSource.onerror = function() { KState.connected = false; };
  },

  failCount: 0,
  offline: false,

  setOffline: function(val) {
    if (this.offline === val) return;
    this.offline = val;
    /* Notify the Kernel House to pause/show offline state */
    if (typeof KHouse !== 'undefined') {
      if (val) {
        KHouse.showOffline();
      } else {
        KHouse.hideOffline();
      }
    }
  }
};
