// Hook a function given by name or absolute address string.

function ptrFrom(arg) {
  if (typeof arg === 'string' && arg.startsWith('0x')) return ptr(arg);
  return null;
}

rpc.exports = {
  monitor: function (nameOrAddr) {
    var target = null;
    var fromString = ptrFrom(nameOrAddr);
    if (fromString) {
      target = fromString;
    } else {
      target = Module.findExportByName(null, nameOrAddr);
    }
    if (!target) {
      send('target not found: ' + nameOrAddr);
      return false;
    }

    Interceptor.attach(target, {
      onEnter(args) {
        this.t = Date.now();
        send(JSON.stringify({event: 'enter', name: nameOrAddr, args: args[0]}));
      },
      onLeave(retval) {
        var dt = Date.now() - this.t;
        send(JSON.stringify({event: 'leave', name: nameOrAddr, ret: retval, dt: dt}));
      }
    });
    send('hooked ' + nameOrAddr + ' @ ' + target);
    return true;
  }
};

