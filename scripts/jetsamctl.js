// attach this to a process with the entitlement `com.apple.private.memorystatus`,
// e.g., dasd:
//   `frida -U dasd -l jetsamctl.js`

const memorystatus_control_addr = Process.getModuleByName('libsystem_kernel.dylib').getExportByName('memorystatus_control');
const memorystatus_control = new NativeFunction(memorystatus_control_addr, 'int', ['int', 'int', 'int', 'pointer', 'int']);
const MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES = 7;
const MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES = 8;


function setMemoryLimit(pid, limitMb) {
    let memlimit_size = 4*4;
    let memlimit = Memory.alloc(memlimit_size); //memorystatus_memlimit_properties_t

    if (memorystatus_control(MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES, pid, 0, memlimit, memlimit_size) == -1) {
        console.error('error getting memory limit properties.');
        return 1;
    }

    console.log(`old limit ${memlimit.readU32()} MiB (active), ${memlimit.add(8).readU32()} MiB (inactive)`);

    memlimit.writeU32(limitMb);
    memlimit.add(8).writeU32(limitMb);

    if (memorystatus_control(MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES, pid, 0, memlimit, memlimit_size) == -1) {
        console.error('error setting memory limit properties.');
        return 1;
    }

    console.log(`applied new limit ${limitMb} MiB active and inactive.`);

}

console.log('run setMemoryLimit(pid, limit in megabytes)');
console.log('Find out pid with Frida: Process.id');