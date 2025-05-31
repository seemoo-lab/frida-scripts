// attach this to a process with the entitlement `com.apple.private.memorystatus`,
// e.g., dasd:
//   `frida -U dasd -l jetsamctl.js`

const memorystatus_control_addr = Process.getModuleByName('libsystem_kernel.dylib').getExportByName('memorystatus_control');
const memorystatus_control = new NativeFunction(memorystatus_control_addr, 'int', ['int', 'int', 'int', 'pointer', 'int']);
const MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT = 6;


function setMemoryLimit(pid, limitMb) {
    // returns 0 if ok, -1 if not permitted
    console.log('returned: ' + memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT, pid, limitMb, new NativePointer(0), 0));
}

console.log('run setMemoryLimit(pid, limit in megabytes)');
console.log('Find out pid with Frida: Process.id');