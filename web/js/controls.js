/* Pause button — minimal subset of kbox's controls.js. */
'use strict';

var KControls = {
  init: function() {
    var btn = document.getElementById('btn-pause');
    if (btn) btn.addEventListener('click', function() {
      KState.paused = !KState.paused;
      btn.textContent = KState.paused ? 'Resume' : 'Pause';
    });
  }
};
