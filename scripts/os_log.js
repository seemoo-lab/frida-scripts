// Fake that all log types are enabled
const isEnabledFunc = Module.findExportByName('libsystem_trace.dylib', 'os_log_type_enabled');
Interceptor.attach(isEnabledFunc, {
  onLeave: function (ret) {
    ret.replace(1);
  }
});

/*
    Function that prints log args.
    Similar to `os_log_impl_flatten_and_send`, which is a highly custom implementation.
    It's *almost* like format strings. But all arguments are in one buffer with type and
    length information, and there's a few more options than what's available for normal
    format strings. So we can't just pass the arguments as a format string somewhere.

    Also, not all functions there are exported and it's super chaotic, so parsing it on
    our own seems to be the simpler solution.

*/
const NSString = ObjC.classes.NSString;
function printLog(args) {
    //let type = args[2]; 
    let format = args[3].readCString();
    let buffer = args[4];
    let num_args = buffer.add(1).readU8(); 

    if (num_args == 0) {
        return format;
    }


    //console.log(format);
    //console.log(buffer.readByteArray(0x50));

    /*

                0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
        00000000  02 03 20 08
                            31 57 64 f9 01 00 00 00 <- ptr
                                                    00 08 <- next type
                                                            c0 a1  .. .1Wd.........
        00000010  e5 04 01 00 00 00 <-- ptr
                                    00 04 02 00 00 00 00 00 00 00  ................
    */


    // Most of this is a normal format string but there's '%.*P' and that one has two entries.
    // It represents a buffer of bytes to be printed, so it's a pointer and a length.

    // can't use the format string as is due to stuff like "%{private}s", "%{bluetooth:OI_STATUS}u", etc.
    format = format.replaceAll(/%({.*?})/g, '%');
    //console.log('format string simplified: ' + format);
    
    // list from https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFStrings/formatSpecifiers.html#//apple_ref/doc/uid/TP40004265
    // while we could call into NSString.stringWithFormat_, Frida doesn't like varargs with vartypes here
    let format_string_parts = format.match(/%({.*?})?.*?([@dDuUxXoOfeEgGcCsSpaAFP])/g)
    if (format_string_parts == null) {
        return format;
    }
    let count = 0;
    let offset = 2;
    //console.log(format);
    //console.log(format_string_parts);
    format_string_parts.forEach((variable) => {
        //console.log(variable);

        // the buffer starts with two bytes meta information (2nd is num of args)
        // each entry has: [1b type] [1b length - 4 or 8] [entry value]
        let type = buffer.add(offset).readU8();
        //console.log('type: 0x' + type.toString(16));
        let l = buffer.add(offset + 1).readU8();
        //console.log('len: 0x' + l.toString(16));

        // 8 byte types (typically pointers)
        if (l == 8) {
            let value = buffer.add(offset + 2).readPointer();
            //console.log('value: ' + value);
            if (variable === '%s' && value != 0 && type >> 4 == 2) { // types 0x20 and 0x22
                format = format.replace(variable, value.readCString());
            } else if (variable === '%@' && value != 0 && type >> 4 == 4) { // types 0x40 and 0x42
                let c = new ObjC.Object(value);
                format = format.replace(variable, c.description());
            } else {
                format = format.replace(variable, value);  // print pointer for remaining types
            }
        } else if (l == 4) {
            let value = buffer.add(offset + 2).readU32();
            //console.log('value: ' + value);

            if (/%.*P/.test(variable) && value != 0) {
                // can be %.*P for arbitrary buffer length or e.g. %.6P for a 6-byte buffer

                // %.*P is a special case: contains a 4-byte length and an 8-byte pointer.
                // we already read the length to value and now have to read that pointer.
                // even if there's %.6P there's duplicate length information!
                
                let p = buffer.add(offset + 2 + 4 + 2).readPointer();
                if (p != 0) {
                    format = format.replace(variable, hexdump(p, {length: value, header: false, ansi: false}));
                }
                offset += 8 + 2;  // adjust for the pointer that we just read 
            } 
            else if (/[xX]/.test(variable)) {  // print hex as hex, but ignore padding
                format = format.replace(variable, value.toString(16));  // preserve hex strings
            } else {
                format = format.replace(variable, value);
            }
        } else if (l == 1) {
            let value = buffer.add(offset + 2).readU8();
            console.log('value: ' + value);
            format = format.replace(variable, value);

        }else {
            console.warn('!!!!!!!!!!!! unknown length!!!!!!! ' + l);
        }
        offset += l + 2;
        count++;
    });

    return format;
}

// Hook all log types and print them in different colors
const log_default = Module.findExportByName('libsystem_trace.dylib', '_os_log_impl')
const log_fault = Module.findExportByName('libsystem_trace.dylib', '_os_log_fault_impl')
const log_debug = Module.findExportByName('libsystem_trace.dylib', '_os_log_debug_impl')
const log_error = Module.findExportByName('libsystem_trace.dylib', '_os_log_error_impl')

Interceptor.attach(log_default, {
    onEnter: function (args) {
        console.log(printLog(args));
    },
});

Interceptor.attach(log_fault, {
    onEnter: function (args) {
        console.error(printLog(args));
    },
});

Interceptor.attach(log_debug, {
    onEnter: function (args) {
        console.log("\x1b[34m" + printLog(args) + "\x1b[0m");  // print debug in blue
    },
});

Interceptor.attach(log_error, {
    onEnter: function (args) {
        console.error(printLog(args));
    },
});

// don't crash...
Process.setExceptionHandler(function(exp) {
    console.warn(JSON.stringify(Object.assign(exp, { _lr: DebugSymbol.fromAddress(exp.context.lr), _pc: DebugSymbol.fromAddress(exp.context.pc) }), null, 2));
    Memory.protect(exp.memory.address, Process.pointerSize, 'rw-');
    return true; // goto PC 
});



console.log('PRINT ALL THE LOGS! \\o/');