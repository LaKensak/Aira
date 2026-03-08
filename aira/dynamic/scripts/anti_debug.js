// Basic anti-debug bypass: returns safe values for common Win32 APIs
// Works on Windows processes; harmless if symbols not found.

function tryHook(moduleName, funcName, impl) {
  try {
    const addr = Module.findExportByName(moduleName, funcName);
    if (!addr) return;
    Interceptor.replace(addr, new NativeCallback(impl, 'int', []));
    send(`[hooked] ${moduleName}!${funcName}`);
  } catch (e) {
    send(`[skip] ${moduleName}!${funcName}: ${e}`);
  }
}

// IsDebuggerPresent -> FALSE
tryHook('kernel32.dll', 'IsDebuggerPresent', function () { return 0; });

// CheckRemoteDebuggerPresent(, BOOL*) -> FALSE and *p=false
try {
  const addr = Module.findExportByName('kernel32.dll', 'CheckRemoteDebuggerPresent');
  if (addr) {
    const f = new NativeFunction(addr, 'bool', ['pointer', 'pointer']);
    Interceptor.replace(addr, new NativeCallback(function (hProc, pBool) {
      if (!pBool.isNull()) Memory.writeU8(pBool, 0);
      return 0;
    }, 'bool', ['pointer', 'pointer']));
    send('[hooked] kernel32!CheckRemoteDebuggerPresent');
  }
} catch (e) { send('[skip] CheckRemoteDebuggerPresent: ' + e); }

// NtSetInformationThread(ThreadHideFromDebugger) -> STATUS_SUCCESS
try {
  const ntdll = Module.findExportByName('ntdll.dll', 'NtSetInformationThread');
  if (ntdll) {
    Interceptor.attach(ntdll, {
      onEnter(args) {
        // args[1] = ThreadInformationClass
        // 0x11 = ThreadHideFromDebugger
        this.isHide = (args[1].toInt32() === 0x11);
      },
      onLeave(retval) {
        if (this.isHide) retval.replace(0); // STATUS_SUCCESS
      }
    });
    send('[hooked] ntdll!NtSetInformationThread');
  }
} catch (e) { send('[skip] NtSetInformationThread: ' + e); }

