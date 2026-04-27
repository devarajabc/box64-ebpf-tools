/* No-op stub.  polling.js (lifted from kbox) calls KTelemetry.onSnapshot()
 * and KTelemetry.onSyscallEvent() — provide empty implementations so we
 * can keep polling.js verbatim and pull future kbox upstream changes. */
'use strict';

var KTelemetry = {
  onSnapshot: function(_snap, _prev) {},
  onSyscallEvent: function(_data) {},
};
