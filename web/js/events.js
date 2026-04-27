/* SSE event feed — adapted from kbox/web/js/events.js (MIT, NCKU 2026)
 * for box64_trace event types: 'process' (fork/exec/clone), 'jit'
 * (large-alloc/churn), 'cow' (CoW page-fault burst). */
'use strict';

var KEvents = {
  feed: null,
  filters: { process: true, jit: true, cow: true },

  init: function() {
    this.feed = document.getElementById('event-feed');
  },

  addEvent: function(type, data) {
    if (!this.feed) return;
    if (type === 'process' && !this.filters.process) return;
    if (type === 'jit' && !this.filters.jit) return;
    if (type === 'cow' && !this.filters.cow) return;

    KState.pushEvent(data);

    var el = document.createElement('div');
    el.className = 'ev ' + type;

    var span = function(cls, txt) {
      var s = document.createElement('span');
      if (cls) s.className = cls;
      s.textContent = txt;
      return s;
    };

    if (type === 'process') {
      el.appendChild(span('ev-name', '[' + (data.action || '?') + ']'));
      el.appendChild(document.createTextNode(' pid=' + data.pid));
      if (data.child_pid) el.appendChild(document.createTextNode(' -> ' + data.child_pid));
      if (data.cmd) el.appendChild(document.createTextNode(' ' + data.cmd));
    } else if (type === 'jit') {
      el.appendChild(span('ev-name', '[jit ' + (data.kind || '?') + ']'));
      el.appendChild(document.createTextNode(' size=' + (data.size || 0) + 'B'));
      if (data.x64_addr) el.appendChild(document.createTextNode(
        ' x64=0x' + data.x64_addr.toString(16)));
      if (data.tid) el.appendChild(document.createTextNode(' tid=' + data.tid));
    } else if (type === 'cow') {
      el.appendChild(span('ev-name', '[cow]'));
      el.appendChild(document.createTextNode(
        ' pid=' + data.pid + ' faults=' + data.faults));
    } else {
      el.appendChild(span('ev-name', '[' + type + ']'));
      el.appendChild(document.createTextNode(' ' + JSON.stringify(data)));
    }

    el.addEventListener('click', function() {
      el.classList.toggle('expanded');
    });

    this.feed.insertBefore(el, this.feed.firstChild);
    while (this.feed.children.length > 500)
      this.feed.removeChild(this.feed.lastChild);
  }
};
