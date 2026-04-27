/* Bootstrap — minimal subset of kbox's main.js (no kernel-house/penguin). */
'use strict';

document.addEventListener('DOMContentLoaded', function() {
  KEvents.init();
  KCharts.init();
  KControls.init();
  KPolling.start();
});
