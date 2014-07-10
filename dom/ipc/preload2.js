/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

// Preload some things, in an attempt to make app startup faster.
//
// This script is run when the preallocated process starts.  It is injected as
// a frame script.

(function (global) {
  "use strict";

  let Cu = Components.utils;
  let Cc = Components.classes;
  let Ci = Components.interfaces;

  Cu.import("resource://gre/modules/AppsServiceChild.jsm");
  dump("TEST: preload2.js");
  DOMApplicationRegistry.resetList();
})(this);
