/*
 Hook into IOKit + HID to inspect drivers during runtime.

 Usage:

    * Attach to existing daemon
        frida -U your_target --no-pause -l IOKit.js

    * Start with new daemon
        frida -U -f /bin/your_target --no-pause -l IOKit.js

*/

// Allow to set mappings between Mach ports and
// IOUserClients as retrieved via launching script
var mappings = [];

var info = Memory.alloc(16);
var table = Memory.alloc(16);
var tableCount = Memory.alloc(16);
var tree = Memory.alloc(16);
var treeCount = Memory.alloc(16);

// step 1: get addresses for kernel functions
var addr_mach_task_self = Module.getExportByName('libsystem_kernel.dylib', 'mach_task_self');
var addr_mach_port_space_info = Module.getExportByName('libsystem_kernel.dylib', 'mach_port_space_info');
var addr_mach_port_kobject = Module.getExportByName('libsystem_kernel.dylib', 'mach_port_kobject');
var addr_mach_port_kobject_description = Module.getExportByName('libsystem_kernel.dylib', 'mach_port_kobject_description');

// step 2: create NativeFunctions
var mach_task_self = new NativeFunction(addr_mach_task_self, 'int', []);
var mach_port_space_info = new NativeFunction(addr_mach_port_space_info, 'int', ['int', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']);
var mach_port_kobject = new NativeFunction(addr_mach_port_kobject, 'int', ['int', 'int', 'pointer', 'pointer'])
var mach_port_kobject_description = new NativeFunction(addr_mach_port_kobject_description, 'int', ['int', 'int', 'pointer', 'pointer', 'pointer'])

// step 3: retrieve task for daemon
var taskself = mach_task_self();
console.log("mach_task_self:", taskself);

// step 4: retrieve mach space info which gets us the task table
var ret = mach_port_space_info(taskself, info, table, tableCount, tree, treeCount);

// step 5: print task table. There are tableCount entries.
const tableBaseAddr = table.readPointer();
var kotype = Memory.alloc(32);
var kaddr = Memory.alloc(32);
var desc = Memory.alloc(32);

for (var i=0; i<tableCount.readU16(); i++) {
    const entry_addr = tableBaseAddr.add(28*i);
    const entry = entry_addr.readU32();
    ret = mach_port_kobject(taskself, entry, kotype, kaddr);
    // kotype == 29 is "IOKIT-CONNECT":
    // https://opensource.apple.com/source/system_cmds/system_cmds-880.100.5/lsmp.tproj/common.h.auto.html
    if (kotype.readU16() == 29) {
        ret = mach_port_kobject_description(taskself, entry, kotype, kaddr, desc);
        const desc_val = desc.readUtf8String();
        // if there is no description, desc will be an empty string
        if (desc_val == '') continue;
        console.log('port:', entry, '| desc:', desc.readUtf8String());
        mappings.push([entry, desc_val]);
    }
}

console.log("done creating mappings.");

// Hook all functions from IOKitLib.h
// https://developer.apple.com/documentation/iokit/iokitlib_h?language=objc
const fnlist = `kern_return_t IOMasterPort(mach_port_t bootstrapPort, mach_port_t *masterPort);
IONotificationPortRef IONotificationPortCreate(mach_port_t masterPort);
void IONotificationPortDestroy(IONotificationPortRef notify);
CFRunLoopSourceRef IONotificationPortGetRunLoopSource(IONotificationPortRef notify);
mach_port_t IONotificationPortGetMachPort(IONotificationPortRef notify);
kern_return_t IONotificationPortSetImportanceReceiver(IONotificationPortRef notify);
void IONotificationPortSetDispatchQueue(IONotificationPortRef notify, dispatch_queue_t queue)
void IODispatchCalloutFromMessage(void *unused, mach_msg_header_t *msg, void *reference);
kern_return_t IOCreateReceivePort(uint32_t msgType, mach_port_t *recvPort);
kern_return_t IOObjectRelease(io_object_t object);
kern_return_t IOObjectRetain(io_object_t object);
kern_return_t IOObjectGetClass(io_object_t object, io_name_t className);
CFStringRef IOObjectCopyClass(io_object_t object)
CFStringRef IOObjectCopySuperclassForClass(CFStringRef classname)
CFStringRef IOObjectCopyBundleIdentifierForClass(CFStringRef classname)
boolean_t IOObjectConformsTo(io_object_t object, const io_name_t className);
boolean_t IOObjectIsEqualTo(io_object_t object, io_object_t anObject);
uint32_t IOObjectGetKernelRetainCount(io_object_t object)
uint32_t IOObjectGetUserRetainCount(io_object_t object)
uint32_t IOObjectGetRetainCount(io_object_t object);
io_object_t IOIteratorNext(io_iterator_t iterator);
void IOIteratorReset(io_iterator_t iterator);
boolean_t IOIteratorIsValid(io_iterator_t iterator);
io_service_t IOServiceGetMatchingService(mach_port_t masterPort, CFDictionaryRef matching CF_RELEASES_ARGUMENT);
kern_return_t IOServiceGetMatchingServices(mach_port_t masterPort, CFDictionaryRef matching CF_RELEASES_ARGUMENT, io_iterator_t *existing);
kern_return_t IOServiceAddNotification(mach_port_t masterPort, const io_name_t notificationType, CFDictionaryRef matching, mach_port_t wakePort, uintptr_t reference, io_iterator_t *notification) DEPRECATED_ATTRIBUTE;
kern_return_t IOServiceAddMatchingNotification(IONotificationPortRef notifyPort, const io_name_t notificationType, CFDictionaryRef matching CF_RELEASES_ARGUMENT, IOServiceMatchingCallback callback, void *refCon, io_iterator_t *notification);
kern_return_t IOServiceAddInterestNotification(IONotificationPortRef notifyPort, io_service_t service, const io_name_t interestType, IOServiceInterestCallback callback, void *refCon, io_object_t *notification);
kern_return_t IOServiceMatchPropertyTable(io_service_t service, CFDictionaryRef matching, boolean_t *matches);
kern_return_t IOServiceGetBusyState(io_service_t service, uint32_t *busyState);
kern_return_t IOServiceWaitQuiet(io_service_t service, mach_timespec_t *waitTime);
kern_return_t IOKitGetBusyState(mach_port_t masterPort, uint32_t *busyState);
kern_return_t IOKitWaitQuiet(mach_port_t masterPort, mach_timespec_t *waitTime);
kern_return_t IOServiceOpen(io_service_t service, task_port_t owningTask, uint32_t type, io_connect_t *connect);
kern_return_t IOServiceRequestProbe(io_service_t service, uint32_t options);
kern_return_t IOServiceAuthorize(io_service_t service, uint32_t options);
int IOServiceOpenAsFileDescriptor(io_service_t service, int oflag);
kern_return_t IOServiceClose(io_connect_t connect);
kern_return_t IOConnectAddRef(io_connect_t connect);
kern_return_t IOConnectRelease(io_connect_t connect);
kern_return_t IOConnectGetService(io_connect_t connect, io_service_t *service);
kern_return_t IOConnectSetNotificationPort(io_connect_t connect, uint32_t type, mach_port_t port, uintptr_t reference);
kern_return_t IOConnectMapMemory(io_connect_t connect, uint32_t memoryType, task_port_t intoTask, vm_address_t *atAddress, vm_size_t *ofSize, IOOptionBits options);
kern_return_t IOConnectMapMemory(io_connect_t connect, uint32_t memoryType, task_port_t intoTask, mach_vm_address_t *atAddress, mach_vm_size_t *ofSize, IOOptionBits options);
kern_return_t IOConnectUnmapMemory(io_connect_t connect, uint32_t memoryType, task_port_t fromTask, vm_address_t atAddress);
kern_return_t IOConnectUnmapMemory(io_connect_t connect, uint32_t memoryType, task_port_t fromTask, mach_vm_address_t atAddress);
kern_return_t IOConnectSetCFProperties(io_connect_t connect, CFTypeRef properties);
kern_return_t IOConnectSetCFProperty(io_connect_t connect, CFStringRef propertyName, CFTypeRef property);
kern_return_t IOConnectCallMethod(mach_port_t connection, uint32_t selector, const uint64_t *input, uint32_t inputCnt, const void *inputStruct, size_t inputStructCnt, uint64_t *output, uint32_t *outputCnt, void *outputStruct, size_t *outputStructCnt)
kern_return_t IOConnectCallAsyncMethod(mach_port_t connection, uint32_t selector, mach_port_t wake_port, uint64_t *reference, uint32_t referenceCnt, const uint64_t *input, uint32_t inputCnt, const void *inputStruct, size_t inputStructCnt, uint64_t *output, uint32_t *outputCnt, void *outputStruct, size_t *outputStructCnt)
kern_return_t IOConnectCallStructMethod(mach_port_t connection, uint32_t selector, const void *inputStruct, size_t inputStructCnt, void *outputStruct, size_t *outputStructCnt)
kern_return_t IOConnectCallAsyncStructMethod(mach_port_t connection, uint32_t selector, mach_port_t wake_port, uint64_t *reference, uint32_t referenceCnt, const void *inputStruct, size_t inputStructCnt, void *outputStruct, size_t *outputStructCnt)
kern_return_t IOConnectCallScalarMethod(mach_port_t connection, uint32_t selector, const uint64_t *input, uint32_t inputCnt, uint64_t *output, uint32_t *outputCnt)
kern_return_t IOConnectCallAsyncScalarMethod(mach_port_t connection, uint32_t selector, mach_port_t wake_port, uint64_t *reference, uint32_t referenceCnt, const uint64_t *input, uint32_t inputCnt, uint64_t *output, uint32_t *outputCnt)
kern_return_t IOConnectTrap0(io_connect_t connect, uint32_t index);
kern_return_t IOConnectTrap1(io_connect_t connect, uint32_t index, uintptr_t p1);
kern_return_t IOConnectTrap2(io_connect_t connect, uint32_t index, uintptr_t p1, uintptr_t p2);
kern_return_t IOConnectTrap3(io_connect_t connect, uint32_t index, uintptr_t p1, uintptr_t p2, uintptr_t p3);
kern_return_t IOConnectTrap4(io_connect_t connect, uint32_t index, uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4);
kern_return_t IOConnectTrap5(io_connect_t connect, uint32_t index, uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4, uintptr_t p5);
kern_return_t IOConnectTrap6(io_connect_t connect, uint32_t index, uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4, uintptr_t p5, uintptr_t p6);
kern_return_t IOConnectAddClient(io_connect_t connect, io_connect_t client);
io_registry_entry_t IORegistryGetRootEntry(mach_port_t masterPort);
io_registry_entry_t IORegistryEntryFromPath(mach_port_t masterPort, const io_string_t path);
io_registry_entry_t IORegistryEntryCopyFromPath(mach_port_t masterPort, CFStringRef path)
kern_return_t IORegistryCreateIterator(mach_port_t masterPort, const io_name_t plane, IOOptionBits options, io_iterator_t *iterator);
kern_return_t IORegistryEntryCreateIterator(io_registry_entry_t entry, const io_name_t plane, IOOptionBits options, io_iterator_t *iterator);
kern_return_t IORegistryIteratorEnterEntry(io_iterator_t iterator);
kern_return_t IORegistryIteratorExitEntry(io_iterator_t iterator);
kern_return_t IORegistryEntryGetName(io_registry_entry_t entry, io_name_t name);
kern_return_t IORegistryEntryGetNameInPlane(io_registry_entry_t entry, const io_name_t plane, io_name_t name);
kern_return_t IORegistryEntryGetLocationInPlane(io_registry_entry_t entry, const io_name_t plane, io_name_t location);
kern_return_t IORegistryEntryGetPath(io_registry_entry_t entry, const io_name_t plane, io_string_t path);
CFStringRef IORegistryEntryCopyPath(io_registry_entry_t entry, const io_name_t plane)
kern_return_t IORegistryEntryGetRegistryEntryID(io_registry_entry_t entry, uint64_t *entryID);
kern_return_t IORegistryEntryCreateCFProperties(io_registry_entry_t entry, CFMutableDictionaryRef *properties, CFAllocatorRef allocator, IOOptionBits options);
CFTypeRef IORegistryEntryCreateCFProperty(io_registry_entry_t entry, CFStringRef key, CFAllocatorRef allocator, IOOptionBits options);
CFTypeRef IORegistryEntrySearchCFProperty(io_registry_entry_t entry, const io_name_t plane, CFStringRef key, CFAllocatorRef allocator, IOOptionBits options) CF_RETURNS_RETAINED;
kern_return_t IORegistryEntryGetProperty(io_registry_entry_t entry, const io_name_t propertyName, io_struct_inband_t buffer, uint32_t *size);
kern_return_t IORegistryEntrySetCFProperties(io_registry_entry_t entry, CFTypeRef properties);
kern_return_t IORegistryEntrySetCFProperty(io_registry_entry_t entry, CFStringRef propertyName, CFTypeRef property);
kern_return_t IORegistryEntryGetChildIterator(io_registry_entry_t entry, const io_name_t plane, io_iterator_t *iterator);
kern_return_t IORegistryEntryGetChildEntry(io_registry_entry_t entry, const io_name_t plane, io_registry_entry_t *child);
kern_return_t IORegistryEntryGetParentIterator(io_registry_entry_t entry, const io_name_t plane, io_iterator_t *iterator);
kern_return_t IORegistryEntryGetParentEntry(io_registry_entry_t entry, const io_name_t plane, io_registry_entry_t *parent);
boolean_t IORegistryEntryInPlane(io_registry_entry_t entry, const io_name_t plane);
CFMutableDictionaryRef IOServiceMatching(const char *name) CF_RETURNS_RETAINED;
CFMutableDictionaryRef IOServiceNameMatching(const char *name) CF_RETURNS_RETAINED;
CFMutableDictionaryRef IOBSDNameMatching(mach_port_t masterPort, uint32_t options, const char *bsdName) CF_RETURNS_RETAINED;
CFMutableDictionaryRef IOOpenFirmwarePathMatching(mach_port_t masterPort, uint32_t options, const char *path) DEPRECATED_ATTRIBUTE;
CFMutableDictionaryRef IORegistryEntryIDMatching(uint64_t entryID) CF_RETURNS_RETAINED;
kern_return_t IOServiceOFPathToBSDName(mach_port_t masterPort, const io_name_t openFirmwarePath, io_name_t bsdName) DEPRECATED_ATTRIBUTE;
kern_return_t OSGetNotificationFromMessage(mach_msg_header_t *msg, uint32_t index, uint32_t *type, uintptr_t *reference, void **content, vm_size_t *size);
kern_return_t IOCatalogueSendData(mach_port_t masterPort, uint32_t flag, const char *buffer, uint32_t size);
kern_return_t IOCatalogueTerminate(mach_port_t masterPort, uint32_t flag, io_name_t description);
kern_return_t IOCatalogueGetData(mach_port_t masterPort, uint32_t flag, char **buffer, uint32_t *size);
kern_return_t IOCatalogueModuleLoaded(mach_port_t masterPort, io_name_t name);
kern_return_t IOCatalogueReset(mach_port_t masterPort, uint32_t flag);
kern_return_t IORegistryDisposeEnumerator(io_enumerator_t enumerator) DEPRECATED_ATTRIBUTE;
kern_return_t IOCompatibiltyNumber(mach_port_t connect, uint32_t *objectNumber) DEPRECATED_ATTRIBUTE;`.split('\n');

fnlist.forEach(hookIt);

function hookIt(fn) {
    const name = fn.split(/[ (]/)[1];

    // Remove everything before the
    // open brace and after the closed
    // brace, so we get argument list.
    const arglist = fn.replace(/\b[\w\s]*\(/,'').replace(/\.*\)[\w\s]*;?/,'').replace(/, \B/, '').replaceAll(', ',',').split(',');
    // -- Debugging --
    // console.log('Function:\t' + name);
    // console.log('Arguments:');
    // for (var i=0; i<arglist.length; i++) {
    //     var type = arglist[i].split(' ');
    //     const name = type.pop();
    //     type = type.join(' ');
    //     console.log('\t' + type + ' -> \t\t\t' + name);
    // }
    // console.log('\n');

    // Create frida hook
    var addr = Module.getExportByName('IOKit', name);
    Interceptor.attach(addr, {
        onEnter: function(args) {
            log_call(name, args, arglist);
        },
        onLeave: function(retval) {
            ret_call(name, retval);
        }
    });
}

function log_call(fname, args, arglist) {
    // Print function name as a header.
    console.log('{^-^} ' + fname + ':');
    // Go through all arguments and print them
    // either directly or dereference the address
    // if it is a pointer and the count is given
    for (var i=0; i<arglist.length; i++) {
        const value = args[i];
        var type = arglist[i].split(' ');
        const name = type.pop();
        type = type.join(' ');

        var s = '> ' + type + ' ' + name + ': ';

        // 3 important checks:
        // Check that it is a pointer,
        // then check the address is not 0
        if (name.includes('*') && value != 0x0) {
            // Check we're not at the last variable
            // so we don't get out of bounds
            if (i != arglist.length-1) {
                const name_without_star = name.slice(1);
                var nextItemType = arglist[i+1].split(' ');
                const nextItemName = nextItemType.pop();
                const nextItemVal = args[i+1];

                // Check if the length is
                // also given and if so, we can
                // safely dereference the pointer.
                if (nextItemName == name_without_star+'Cnt') {
                    console.log(s);
                    console.log(value.readByteArray(parseInt(nextItemVal)));
                    continue;
                }
            }
            
            // Alternatively, in case it's
            // a pointer to a variable of known
            // type, we can also dereference properly.

            // https://opensource.apple.com/source/xnu/xnu-792/osfmk/mach/port.h.auto.html
            // typedef ipc_port_t mach_port_t;

            // https://opensource.apple.com/source/xnu/xnu-792/osfmk/mach/port.h.auto.html
            // typedef struct ipc_port *ipc_port_t

            // https://opensource.apple.com/source/xnu/xnu-201/osfmk/ipc/ipc_port.h.auto.html
            // struct ipc_port { ... }
            if (type == 'mach_port_t') {
                console.log(s + value);
                continue;
            }
            else if (type == 'io_iterator_t') {
                console.log(s + value.readU8());
                continue;
            }
            else if (type == 'const char') {
                console.log(s + value.readUtf8String());
                continue;
            }
            else if (type == 'mach_msg_header_t') {
                console.log(s);
                const mapping = mappings.find(function (el) { return el[0] == value.add(8).readU32() });
                console.log('\t>> mach_msg_bits msgh_bits: 0x' + value.readU32().toString(16).padStart(8,'0'));
                console.log('\t>> mach_msg_size_t msgh_size: 0x' + value.add(4).readU32().toString(16).padStart(8,'0'));
                
                const machport = '\t>> mach_port_t msgh_remote_port: 0x' + value.add(8).readU32().toString(16).padStart(8,'0');
                if (mapping == undefined || mapping[1] == undefined) {
                    console.log(machport);
                }
                else {
                    console.log(machport + ' ==> ' + mapping[1]);
                }
                
                
                console.log('\t>> mach_port_t msgh_local_port: 0x' + value.add(12).readU32().toString(16).padStart(8,'0'));
                console.log('\t>> mach_msg_size_t msgh_reserved: 0x' + value.add(16).readU32().toString(16).padStart(8,'0'));
                console.log('\t>> mach_msg_id_t msgh_id: 0x' + value.add(20).readU32().toString(16).padStart(8,'0'));
                // console.log(s + '\n' + hexdump(value));
                continue;
            }
            // else {
            //     console.log(s + type);
            // }
        }
        // non-pointer (*) types
        else if (type == 'mach_port_t') {
            const mapping = mappings.find(function (el) { return el[0] == parseInt(value) });
            if (mapping != undefined && mapping[1] != undefined) {
                console.log(s + value + ' => ' + mapping[1]);
            }
            else {
                console.log(s + value);
            }
            continue;
        }
        else if (type == 'CFStringRef') {
            // - Debugging -
            // for(var i=0;i<16;i++) {
            //     console.log(hexdump(value.add(i*16).readPointer()));
            // }

            // console.log(hexdump(value));

            // - From https://opensource.apple.com/source/CF/CF-476.18/CFString.c.auto.html -
            // struct __CFString {
            //     CFRuntimeBase base;
            //     union { // In many cases the allocated structs are smaller than these
            //         struct __inline1 {
            //             CFIndex length;
            //         } inline1;                                      // Bytes follow the length
            //         struct __notInlineImmutable1 {
            //             void *buffer;                               // Note that the buffer is in the same place for all non-inline variants of CFString
            //             CFIndex length;                             
            //             CFAllocatorRef contentsDeallocator;     // Optional; just the dealloc func is used
            //         } notInlineImmutable1;                          // This is the usual not-inline immutable CFString
            //         struct __notInlineImmutable2 {
            //             void *buffer;
            //             CFAllocatorRef contentsDeallocator;     // Optional; just the dealloc func is used
            //         } notInlineImmutable2;                          // This is the not-inline immutable CFString when length is stored with the contents (first byte)
            //         struct __notInlineMutable notInlineMutable;
            //     } variants;
            // };

            // typedef struct __CFRuntimeBase {
            //     uintptr_t _cfisa;
            //     uint8_t _cfinfo[4];
            // #if __LP64__
            //     uint32_t _rc;
            // #endif
            // } CFRuntimeBase;

            // typedef long CFIndex;

            // This means the 2 string buffers are at the pointers
            // sitting at base address + 16 and base address + 48.

            const cfstring_base = new NativePointer(value);
            const buffer1 = value.add(16).readPointer().readUtf8String();
            const buffer2 = value.add(48).readPointer().readUtf8String();
            console.log(s + buffer1);
            continue;
        }
        else if (type.includes('CFDictionaryRef')) {
            // Frida can handle CFDictionaries natively as Objective-C objects
            const cfdict = new NativePointer(value);
            console.log(s + cfdict + '\nDict: \n' + new ObjC.Object(value));
            continue;
        }

        // If anything went wrong,
        // just print the memory location.
        console.log(s + value);
    }
    // print a newline at the end
    console.log('');

}

function ret_call(fname, retval) {

    // print the mach port that the service is going to use
    if (fname.includes('IOIteratorNext')) {
        if (retval != 0x0) {
            console.log('< io_service_t ' + retval + '\n');
        }
    }
}

// var addr_mach = Module.getExportByName('libSystem.B.dylib', 'mach_msg');
// Interceptor.attach(addr_mach, {
//     onEnter: function(args) {
//         const name = 'mach_msg';
//         const arglist = ['mach_msg_header_t *msg', 'mach_msg_option_t option', 'mach_msg_size_t send_size', 'mach_msg_size_t rcv_size', 'mach_port_name_t rcv_name', 'mach_msg_timeout_t timeout', 'mach_port_name_t notify'];
//         log_call(name, args, arglist);
//     }
// });
