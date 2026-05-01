(() => {
  const STATUS_PATH = globalThis.__bb_chain_status_path || "/private/var/tmp/brokenblade_chain_status.log";
  const COMPLETE_MARKER = globalThis.__bb_chain_status_complete_marker || "[PE] start() completed successfully";
  const ALERT_TITLE = globalThis.__bb_chain_alert_title || "LightSaber";
  const PROGRESS_TEXT = globalThis.__bb_chain_progress_text || "LS chain in progress";
  const COMPLETE_TEXT = globalThis.__bb_chain_complete_text || "LS chain complete";
  const POLL_INTERVAL_US = 1500000;
  const POLL_MAX_ITERS = 2400;
  const DONE_POST_ITERS = 3;
  const PROGRESS_REFRESH_ITERS = 4;
  const MAX_READ_BYTES = 16384;
  const MAIN_DISPATCH_TIMEOUT_MS = 3500;
  const MAIN_DISPATCH_CANCEL_GRACE_MS = 500;

  class Native {
    static #baseAddr;
    static #dlsymAddr;
    static #memcpyAddr;
    static #mallocAddr;
    static mem = 0n;
    static memSize = 0x4000;
    static #argMem = 0n;
    static #argPtr = 0n;
    static #dlsymCache = {};

    static init() {
      const buff = new BigUint64Array(nativeCallBuff);
      this.#baseAddr = buff[20];
      this.#dlsymAddr = buff[21];
      this.#memcpyAddr = buff[22];
      this.#mallocAddr = buff[23];
      this.mem = this.#nativeCallAddr(this.#mallocAddr, BigInt(this.memSize));
      this.#argMem = this.#nativeCallAddr(this.#mallocAddr, 0x1000n);
      this.#argPtr = this.#argMem;
    }

    static write(ptr, buff) {
      if (!ptr) return false;
      const buff8 = new Uint8Array(nativeCallBuff);
      let offs = 0;
      let left = buff.byteLength;
      while (left) {
        let len = left > 0x1000 ? 0x1000 : left;
        buff8.set(new Uint8Array(buff, offs, len), 0x1000);
        this.#nativeCallAddr(this.#memcpyAddr, ptr + BigInt(offs), this.#baseAddr + 0x1000n, BigInt(len));
        left -= len;
        offs += len;
      }
      return true;
    }

    static read(ptr, length) {
      const buff = new ArrayBuffer(length);
      const buff8 = new Uint8Array(buff);
      let offs = 0;
      let left = length;
      while (left) {
        let len = left > 0x1000 ? 0x1000 : left;
        this.#nativeCallAddr(this.#memcpyAddr, this.#baseAddr + 0x1000n, ptr + BigInt(offs), BigInt(len));
        buff8.set(new Uint8Array(nativeCallBuff, 0x1000, len), offs);
        left -= len;
        offs += len;
      }
      return buff;
    }

    static readString(ptr, len = 512) {
      return this.bytesToString(this.read(ptr, len), false);
    }

    static writeString(ptr, str) {
      this.write(ptr, this.stringToBytes(str, true));
    }

    static bytesToString(bytes, includeNullChar = true) {
      const bytes8 = new Uint8Array(bytes);
      let str = "";
      for (let i = 0; i < bytes8.length; i++) {
        if (!includeNullChar && !bytes8[i]) break;
        str += String.fromCharCode(bytes8[i]);
      }
      return str;
    }

    static stringToBytes(str, nullTerminated = false) {
      const buff = new ArrayBuffer(str.length + (nullTerminated ? 1 : 0));
      const s8 = new Uint8Array(buff);
      for (let i = 0; i < str.length; i++) s8[i] = str.charCodeAt(i) & 0xff;
      if (nullTerminated) s8[str.length] = 0;
      return buff;
    }

    static bridgeInfo() {
      const buff = new BigUint64Array(nativeCallBuff);
      return { jsContextObj: buff[33] };
    }

    static #toNative(value) {
      if (!value) return 0n;
      if (typeof value === "string") {
        const ptr = this.#argPtr;
        this.writeString(ptr, value);
        this.#argPtr += BigInt(value.length + 1);
        return ptr;
      }
      if (typeof value === "bigint") return value;
      return BigInt(value);
    }

    static #dlsym(name) {
      if (!name) return 0n;
      let addr = this.#dlsymCache[name];
      if (addr) return addr;
      const RTLD_DEFAULT = 0xfffffffffffffffen;
      const nameBytes = this.stringToBytes(name, true);
      new Uint8Array(nativeCallBuff).set(new Uint8Array(nameBytes), 0x1000);
      addr = this.#nativeCallAddr(this.#dlsymAddr, RTLD_DEFAULT, this.#baseAddr + 0x1000n);
      if (addr) this.#dlsymCache[name] = addr;
      return addr;
    }

    static #nativeCallAddr(addr, x0 = 0n, x1 = 0n, x2 = 0n, x3 = 0n, x4 = 0n, x5 = 0n, x6 = 0n, x7 = 0n) {
      const buff = new BigInt64Array(nativeCallBuff);
      buff[0] = addr;
      buff[100] = x0;
      buff[101] = x1;
      buff[102] = x2;
      buff[103] = x3;
      buff[104] = x4;
      buff[105] = x5;
      buff[106] = x6;
      buff[107] = x7;
      invoker();
      return buff[200];
    }

    static callSymbol(name, x0, x1, x2, x3, x4, x5, x6, x7) {
      this.#argPtr = this.#argMem;
      x0 = this.#toNative(x0);
      x1 = this.#toNative(x1);
      x2 = this.#toNative(x2);
      x3 = this.#toNative(x3);
      x4 = this.#toNative(x4);
      x5 = this.#toNative(x5);
      x6 = this.#toNative(x6);
      x7 = this.#toNative(x7);
      const funcAddr = this.#dlsym(name);
      if (!funcAddr) {
        this.#argPtr = this.#argMem;
        return 0n;
      }
      const ret64 = this.#nativeCallAddr(funcAddr, x0, x1, x2, x3, x4, x5, x6, x7);
      this.#argPtr = this.#argMem;
      if (ret64 === 0xffffffffffffffffn) return -1;
      if (ret64 < 0xffffffffn && ret64 > -0xffffffffn) return Number(ret64);
      return ret64;
    }
  }

  function u64(v) {
    if (!v) return 0n;
    return BigInt.asUintN(64, BigInt(v));
  }

  function isNonZero(v) {
    return u64(v) !== 0n;
  }

  function sel(name) {
    return Native.callSymbol("sel_registerName", name);
  }

  function objc(obj, selectorName, ...args) {
    return Native.callSymbol("objc_msgSend", obj, sel(selectorName), ...args);
  }

  function cfstr(str) {
    return Native.callSymbol("CFStringCreateWithCString", 0n, str, 0x08000100);
  }

  function log(msg) {
    try {
      const tagged = "[CHAIN-OVL] " + msg;
      const ptr = Native.callSymbol("malloc", BigInt(tagged.length + 1));
      if (!ptr) return;
      Native.writeString(ptr, tagged);
      Native.callSymbol("syslog", 5, ptr);
      Native.callSymbol("free", ptr);
    } catch (_) {}
  }

  function sleepWithoutNative(ms) {
    try {
      if (typeof Atomics === "object" && typeof Atomics.wait === "function" && typeof SharedArrayBuffer === "function") {
        if (!globalThis.__bb_chain_overlay_sleep_i32) {
          globalThis.__bb_chain_overlay_sleep_i32 = new Int32Array(new SharedArrayBuffer(4));
        }
        Atomics.wait(globalThis.__bb_chain_overlay_sleep_i32, 0, 0, ms);
        return;
      }
    } catch (_) {}
    const deadline = Date.now() + ms;
    while (Date.now() < deadline) {}
  }

  function waitForMainTicket(ticket, timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (globalThis.__bb_chain_overlay_main_done_ticket === ticket) return true;
      sleepWithoutNative(25);
    }
    return globalThis.__bb_chain_overlay_main_done_ticket === ticket;
  }

  function runOnMainEvaluate(script, ticket) {
    const jsctxObj = globalThis.__bb_chain_overlay_jsctx_obj;
    if (!isNonZero(jsctxObj)) {
      log("main evaluate skipped: jsctxObj missing");
      return "main-dispatch-unavailable";
    }
    const s = cfstr(script);
    if (!isNonZero(s)) {
      log("main evaluate skipped: script cfstr failed");
      return "main-dispatch-cfstr-failed";
    }
    globalThis.__bb_chain_overlay_main_done_ticket = 0;
    globalThis.__bb_chain_overlay_main_started_ticket = 0;
    globalThis.__bb_chain_overlay_cancel_ticket = 0;
    objc(jsctxObj, "performSelectorOnMainThread:withObject:waitUntilDone:", sel("evaluateScript:"), s, 0);

    // Do not CFRelease `s` here. With waitUntilDone:NO, Foundation keeps the
    // object alive until the main runloop consumes it. Releasing from this
    // worker thread can race the main-thread evaluateScript: handoff.
    if (waitForMainTicket(ticket, MAIN_DISPATCH_TIMEOUT_MS)) return "done";

    // From this point on the worker must assume a late main-thread delivery is
    // still possible. If the main update already started, never touch the
    // native bridge again from this worker; the main thread may still own
    // nativeCallBuff.
    if (globalThis.__bb_chain_overlay_main_started_ticket === ticket) return "main-update-timeout";

    // If the script is only queued, cancel it with a JS-only flag, wait without
    // native calls, then let the caller bail out after the queued main script
    // has either observed the cancel or stayed undelivered.
    globalThis.__bb_chain_overlay_cancel_ticket = ticket;
    sleepWithoutNative(MAIN_DISPATCH_CANCEL_GRACE_MS);
    if (globalThis.__bb_chain_overlay_main_done_ticket === ticket) return "done";
    return "main-queue-timeout";
  }

  function mainUpdateOverlay(ticket) {
    globalThis.__bb_chain_overlay_main_started_ticket = ticket;
    try {
      if (globalThis.__bb_chain_overlay_cancel_ticket === ticket) return false;
      return updateOverlay();
    } catch (e) {
      log("main update error " + String(e));
      return false;
    } finally {
      globalThis.__bb_chain_overlay_main_done_ticket = ticket;
    }
  }

  function getStatusFileEnd() {
    const fd = Native.callSymbol("open", STATUS_PATH, 0);
    if (Number(fd) < 0) return 0;
    try {
      const endRaw = Native.callSymbol("lseek", fd, 0n, 2n);
      const end = Number(endRaw);
      return end > 0 ? end : 0;
    } finally {
      Native.callSymbol("close", fd);
    }
  }

  function readStatusFileFrom(startOffset) {
    const fd = Native.callSymbol("open", STATUS_PATH, 0);
    if (Number(fd) < 0) return "";
    let buf = 0n;
    try {
      const endRaw = Native.callSymbol("lseek", fd, 0n, 2n);
      const end = Number(endRaw);
      if (!end || end < 0) return "";
      let start = startOffset > 0 && end >= startOffset ? startOffset : 0;
      if (end <= start) return "";
      if (end - start > MAX_READ_BYTES) start = end - MAX_READ_BYTES;
      Native.callSymbol("lseek", fd, BigInt(start), 0n);
      const want = end - start;
      buf = Native.callSymbol("malloc", BigInt(want + 1));
      if (!buf || buf === 0n) return "";
      const got = Number(Native.callSymbol("read", fd, buf, want));
      if (got <= 0) return "";
      return Native.bytesToString(Native.read(buf, got), false);
    } finally {
      if (buf) Native.callSymbol("free", buf);
      Native.callSymbol("close", fd);
    }
  }

  function hasCompletionMarker(startOffset) {
    return readStatusFileFrom(startOffset).indexOf(COMPLETE_MARKER) >= 0;
  }

  function topPresenter() {
    const UIApplication = Native.callSymbol("objc_getClass", "UIApplication");
    if (!isNonZero(UIApplication)) {
      log("UIApplication missing");
      return 0n;
    }
    const app = objc(UIApplication, "sharedApplication");
    if (!isNonZero(app)) {
      log("sharedApplication missing");
      return 0n;
    }
    let win = objc(app, "keyWindow");
    if (!isNonZero(win)) {
      const windows = objc(app, "windows");
      if (isNonZero(windows)) win = objc(windows, "lastObject");
    }
    if (!isNonZero(win)) {
      log("presenter window missing");
      return 0n;
    }
    let vc = objc(win, "rootViewController");
    if (!isNonZero(vc)) {
      log("rootViewController missing");
      return 0n;
    }
    for (let i = 0; i < 8; i++) {
      const next = objc(vc, "presentedViewController");
      if (!isNonZero(next)) break;
      vc = next;
    }
    return vc;
  }

  function ensureAlert(text) {
    const existing = globalThis.__bb_chain_overlay_alert_controller;
    if (isNonZero(existing)) return existing;

    const UIAlertController = Native.callSymbol("objc_getClass", "UIAlertController");
    const UIAlertAction = Native.callSymbol("objc_getClass", "UIAlertAction");
    if (!isNonZero(UIAlertController) || !isNonZero(UIAlertAction)) {
      log("UIAlertController/UIAlertAction missing");
      return 0n;
    }

    const titleRef = cfstr(ALERT_TITLE);
    const msgRef = cfstr(text || PROGRESS_TEXT);
    const okRef = cfstr("OK");
    if (!isNonZero(titleRef) || !isNonZero(msgRef) || !isNonZero(okRef)) {
      if (isNonZero(titleRef)) Native.callSymbol("CFRelease", titleRef);
      if (isNonZero(msgRef)) Native.callSymbol("CFRelease", msgRef);
      if (isNonZero(okRef)) Native.callSymbol("CFRelease", okRef);
      return 0n;
    }

    const alert = objc(UIAlertController, "alertControllerWithTitle:message:preferredStyle:", titleRef, msgRef, 1n);
    const action = isNonZero(alert) ? objc(UIAlertAction, "actionWithTitle:style:handler:", okRef, 0n, 0n) : 0n;
    Native.callSymbol("CFRelease", titleRef);
    Native.callSymbol("CFRelease", msgRef);
    Native.callSymbol("CFRelease", okRef);
    if (!isNonZero(alert) || !isNonZero(action)) return 0n;

    objc(alert, "addAction:", action);
    objc(alert, "retain");

    globalThis.__bb_chain_overlay_alert_controller = alert;
    log("UIAlertController ready ptr=0x" + u64(alert).toString(16));
    return alert;
  }

  function showAlertText(text) {
    let s = String(text || PROGRESS_TEXT);
    if (s.length > 120) s = s.slice(0, 117) + "...";
    const count = Number(globalThis.__bb_chain_overlay_post_count || 0);
    if (count < 3 || globalThis.__bb_chain_overlay_done) log("showing alert text: " + s);
    const alert = ensureAlert(s);
    if (!isNonZero(alert)) return false;

    const titleRef = cfstr(ALERT_TITLE);
    const msgRef = cfstr(s);
    if (!isNonZero(titleRef) || !isNonZero(msgRef)) {
      if (isNonZero(titleRef)) Native.callSymbol("CFRelease", titleRef);
      if (isNonZero(msgRef)) Native.callSymbol("CFRelease", msgRef);
      return false;
    }

    try {
      objc(alert, "setTitle:", titleRef);
      objc(alert, "setMessage:", msgRef);
      if (!isNonZero(objc(alert, "presentingViewController")) && !isNonZero(objc(alert, "isBeingPresented"))) {
        const presenter = topPresenter();
        if (!isNonZero(presenter)) return false;
        objc(presenter, "presentViewController:animated:completion:", alert, 1n, 0n);
      }
      globalThis.__bb_chain_overlay_post_count = count + 1;
      if (count < 3 || globalThis.__bb_chain_overlay_done) log("alert text posted");
      return true;
    } finally {
      Native.callSymbol("CFRelease", titleRef);
      Native.callSymbol("CFRelease", msgRef);
    }
  }

  function updateOverlay() {
    return showAlertText(globalThis.__bb_chain_overlay_text || PROGRESS_TEXT);
  }

  function dispatchOverlayText(text, ticket) {
    globalThis.__bb_chain_overlay_text = text;
    return runOnMainEvaluate("try{__bb_chain_overlay_main_update(" + ticket + ");}catch(e){try{__bb_chain_overlay_log('main dispatch err '+e);}catch(_){ }finally{__bb_chain_overlay_main_done_ticket=" + ticket + ";}}", ticket);
  }

  function exitWorkerThread(reason) {
    try {
      const isMain = Number(Native.callSymbol("pthread_main_np"));
      if (isMain === 1) {
        log("skip pthread_exit on main thread reason=" + reason);
        return;
      }
      log("pthread_exit worker reason=" + reason);
      Native.callSymbol("pthread_exit", 0n);
      log("pthread_exit returned unexpectedly");
    } catch (e) {
      try { log("pthread_exit failed " + String(e)); } catch (_) {}
    }
  }

  try {
    Native.init();
    globalThis.__bb_chain_overlay_jsctx_obj = Native.bridgeInfo().jsContextObj;
    globalThis.__bb_chain_overlay_log = log;
    globalThis.__bb_chain_overlay_update = updateOverlay;
    globalThis.__bb_chain_overlay_main_update = mainUpdateOverlay;
    const statusStartOffset = getStatusFileEnd();
    log("entry statusPath=" + STATUS_PATH + " mode=native-alert startOffset=" + statusStartOffset);
    let doneIters = 0;
    let exitReason = "max-iters";
    let ticket = 1;
    let mainStatus = dispatchOverlayText(PROGRESS_TEXT, ticket++);
    if (mainStatus !== "done") {
      exitReason = mainStatus;
      if (mainStatus === "main-update-timeout") {
        while (true) sleepWithoutNative(60000);
      }
    }
    for (let i = 0; i < POLL_MAX_ITERS; i++) {
      if (exitReason !== "max-iters") break;
      globalThis.__bb_chain_overlay_done = hasCompletionMarker(statusStartOffset);
      if (globalThis.__bb_chain_overlay_done) {
        doneIters++;
        if (doneIters === 1) log("completion marker observed");
        mainStatus = dispatchOverlayText(COMPLETE_TEXT, ticket++);
        if (mainStatus !== "done") {
          exitReason = mainStatus;
          if (mainStatus === "main-update-timeout") {
            while (true) sleepWithoutNative(60000);
          }
          break;
        }
        if (doneIters >= DONE_POST_ITERS) {
          exitReason = "complete";
          break;
        }
      } else if ((i + 1) % PROGRESS_REFRESH_ITERS === 0) {
        mainStatus = dispatchOverlayText(PROGRESS_TEXT, ticket++);
        if (mainStatus !== "done") {
          exitReason = mainStatus;
          if (mainStatus === "main-update-timeout") {
            while (true) sleepWithoutNative(60000);
          }
          break;
        }
      }
      Native.callSymbol("usleep", POLL_INTERVAL_US);
    }
    log("poll loop exit done=" + !!globalThis.__bb_chain_overlay_done + " reason=" + exitReason);
    exitWorkerThread(exitReason);
  } catch (e) {
    try { log("fatal " + String(e)); } catch (_) {}
    try { exitWorkerThread("fatal"); } catch (_) {}
  }
})();
