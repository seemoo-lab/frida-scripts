// Fake that all log types are enabled
let isEnabledFunc = Module.findExportByName('libsystem_trace.dylib', 'os_log_type_enabled');
Interceptor.attach(isEnabledFunc, {
  onLeave: function (ret) {
    ret.replace(1);
  }
});

// generic function to print log args
const NSString = ObjC.classes.NSString;
function printLog(args) {
    let type = args[2]; 
    let format = args[3].readCString();
    let buffer = args[4];
    //let num_args = buffer.add(1).readU8();  // as specified by format instead of string
    //console.log(buffer.readByteArray(0x40));
    let num_args = (format.match(/%({.*?})?.*?([@dDuUxXoOfeEgGcCsSpaAF])/g) || []).length; // number of args as counted in string
    //console.log('% in string ' + num_args_string + ' vs number in buffer ' + num_args);
    // TODO number different on format string '%.*P'

    if (num_args == 0) {
        return format;
    }

    /*

                0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
        00000000  02 03 20 08
                            31 57 64 f9 01 00 00 00 <- ptr
                                                    00 08 <- next type
                                                            c0 a1  .. .1Wd.........
        00000010  e5 04 01 00 00 00 <-- ptr
                                    00 04 02 00 00 00 00 00 00 00  ................
    */


    // can't use the format string as is due to stuff like "%{private}s", "%{bluetooth:OI_STATUS}u", etc.
    format = format.replaceAll(/%({.*?})/g, '%');
    //console.log('format string simplified: ' + format);
    
    // list from https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFStrings/formatSpecifiers.html#//apple_ref/doc/uid/TP40004265
    // while we could call into NSString.stringWithFormat_, Frida doesn't like varargs with vartypes here
    let format_string_parts = format.match(/%({.*?})?.*?([@dDuUxXoOfeEgGcCsSpaAF])/g)
    if (format_string_parts == null) {
        return format;
    }
    let count = 0;
    let format_string_values = [];
    let offset = 2;
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
            let pos = buffer.add(offset + 2).readPointer();
            format_string_values[count] = pos;
            if (variable === '%s') {
                format = format.replace(variable, pos.readCString());
            } else if (variable === '%@') {
                format = format.replace(variable, new ObjC.Object(pos));
            } else {
                format = format.replace(variable, pos);  // print pointer for remaining types
            }
        } else if (l == 4) {
            let pos = buffer.add(offset + 2).readU32();
            format_string_values[count] = pos;
            if (variable === '%x' || variable === '%X') {
                format = format.replace(variable, pos.toString(16));  // preserve hex strings
            } else {
                format = format.replace(variable, pos);
            }
        } else {
            console.warn('!!!!!!!!!!!! unknown length!!!!!!! ' + l);
            format_string_values[count] = new NativePointer(0x0);  //TODO
        }
        offset += l + 2;
        count++;
    });

    //console.log('format string values: ')
    //console.log(format_string_values);

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
        console.debug(printLog(args));
    },
});

Interceptor.attach(log_error, {
    onEnter: function (args) {
        console.error(printLog(args));
    },
});



console.log('Printing log messages!');