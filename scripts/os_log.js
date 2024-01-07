

/*
    Function that prints OS Log args.

    Apple's clang emits built-in calls to create the OS log buffer of the correct size and
    then also fill in the OS Log buffer. Before creating the built-in calls, OS Log takes
    a format string and a variable number of arguments. clang then emits the buffer size
    along with the instructions to fill the stack buffer. To this end, it first parses
    the format string and builds an internal layout struct it fills with the arguments
    (compile time). Then, clang iterates over the layout struct items and emits instructions
    that end up in the binary.

    CGBuiltin.cpp:          Builtin::BI__builtin_os_log_format
    OSLog.cpp:              clang::analyze_os_log::computeOSLogBufferLayout
    PrintfFormatString.cpp: clang::analyze_format_string::ParsePrintfString

    This might be done to accelerate log message parsing, and we can use the open part
    of the implementation to name things correctly.

    At runtime, the logs are parsed by `libsystem_trace.dylib`, and the most important
    part of the parser is contained in `os_log_impl_flatten_and_send`. Many parts in the
    code don't contain symbols and it's difficult to call into this with Frida.

    Items are defined in OSLog.h as follows:
        4 Bits kind (upper nibble)
             0 ScalarKind
             1 CountKind
             2 StringKind
             3 PointerKind
             4 ObjCObjKind
        4 Bits Public/Private (lower nibble), we ignore this to print them all

    As defined in HandlePrintfSpecifier, each of these has different cases to handle:
         * "%f", "%d"... scalar and can be 4 bytes or even 1 bytes -- everything else is 8 bytes
         * "%s" pointer to null-terminated string
         * "%.*s" strlen (arg), pointer to string
         * "%.16s" strlen (non-arg), pointer to string
         * "%.*P" len (arg), pointer to data
         * "%.16P" len (non-arg), pointer to data
         * "%@" pointer to objc object
    
    There are a lot of types to handle, including length modifiers etc. in these format strings.
    We mostly care about printing the numbers at all, it's a bit quick&dirty. Handling them all
    might take too much time.

*/

const kind = {
    ScalarKind: 0,
    CountKind: 1,
    StringKind: 2,
    PointerKind: 3,
    ObjCObjKind: 4
}

const NSString = ObjC.classes.NSString;

function printLog(args) {
    // Parse the null-terminated format string
    let StringArg = args[3].readCString();
    let BufAddr = args[4];
    let BufLen = parseInt(args[5]);

    // The Buffer starts with two bytes: a summary byte and numArgs.
    let numArgs = BufAddr.add(1).readU8(); 

    if (numArgs == 0) {
        return StringArg;
    }

    // Can't use the format string as is due to stuff like "%{private}s", "%{bluetooth:OI_STATUS}u", etc.
    // Just replace everything in {} as we ignore public/private.
    StringArg = StringArg.replaceAll(/%({.*?})/g, '%');
    
    // Mostly normal format strings that we can match now, item by item.
    // In our case it's easier to iterate through the format string, as the raw buffer sometimes has
    // composed values that we want to combine and then replace one format string value with it.
    // For simplicity, we assume any characters are valid length modifiers (see FormatString.h).
    // We consider all conversion modifiers (see PrintfFormatString.cpp).
    let formatStringItems = StringArg.match(/%({.*?})?.*?([%AEFGXacdefginopsuxCSP@mbryDOUZ])/g)
    if (formatStringItems == null) {
        return StringArg;
    }

    // Skip first two bytes: summary and numArgs
    let bufferOffset = 2;
    let itemCount = 0;

    formatStringItems.forEach((variable) => {
        // each item has: [1b type] [1b length] [entry value]
        let argDescriptor = BufAddr.add(bufferOffset).readU8();
        let argKind = argDescriptor >> 4;
        let argSize = BufAddr.add(bufferOffset + 1).readU8();

        // StringKind, ObjcObjKind, PointerKind are all very similar 8-byte types
        if (argKind == kind.StringKind) {
            let value = BufAddr.add(bufferOffset + 2).readPointer();
            if (value != 0) {
                StringArg = StringArg.replace(variable, value.readCString());
            }
        } else if (argKind == kind.PointerKind) {
            let value = BufAddr.add(bufferOffset + 2).readPointer();
            if (value != 0) {
                StringArg = StringArg.replace(variable, value.toString(16)); 
            }

        } else if (argKind == kind.ObjCObjKind) {
            let value = BufAddr.add(bufferOffset + 2).readPointer();
            if (value != 0) {
                let c = new ObjC.Object(value);
                StringArg = StringArg.replace(variable, c.description());
            }
        }
        // CountKind describes size of next element, which is StringKind or PointerKind.
        // CountKind is 4 bytes long.
        // StringKind and PointerKind then point to a String or Pointer and at that position we want
        // to read as many bytes as the count indicated.
        else if (argKind == kind.CountKind) {
            let value = BufAddr.add(bufferOffset + 2).readU32();
            let pointsToKind = BufAddr.add(bufferOffset + 2 + 4).readU8() >> 4;
            let pointerValue = BufAddr.add(bufferOffset + 2 + 4 + 2).readPointer();

            if (pointerValue != 0) {
                if (pointsToKind == kind.PointerKind) {
                    StringArg = StringArg.replace(variable, hexdump(pointerValue, {length: value, header: false, ansi: false}));
                } else if (pointsToKind == kind.StringKind) {
                    StringArg = StringArg.replace(variable, pointerValue.readCString(value));
                }
            } else {
                StringArg = StringArg.replace(variable, 'null');
            }

            // advance buffer by PointerKind/StringKind
            bufferOffset += 8 + 2; 
        }
        // ScalarKind are regular numbers but can have different sizes
        else if (argKind == kind.ScalarKind) {
            let value;

            // read as many bytes as the ScalarKind has
            if (argSize == 1) {
                value = BufAddr.add(bufferOffset + 2).readU8();
            } else if (argSize == 4) {
                value = BufAddr.add(bufferOffset + 2).readU32();
            } else if (argSize == 8) {
                value = BufAddr.add(bufferOffset + 2).readPointer();
            }

            // differentiate between hex vs decimal output
            if (/[xX]/.test(variable)) {
                StringArg = StringArg.replace(variable, value.toString(16));  // preserve hex strings
            }
            // '%0.*d' consists of two ScalarKinds where the first is number of digits
            else if(variable === '%0.*d') {
                let realValue = BufAddr.add(bufferOffset + 2 + 4 + 2).readU32();
                StringArg = StringArg.replace(variable, realValue);
                bufferOffset += 4 + 2;  // advance buffer
            }
            // signed integers
            else if (variable === '%d' || variable === '%i') {
                StringArg = StringArg.replace(variable, (value << 32) >> 32);
            }
            else {
                StringArg = StringArg.replace(variable, value);
            }

            // TODO readability would be improved by adding further special cases here,
            // such as %f etc. or even considering length modifiers

        }
        bufferOffset += argSize + 2;    // advance offset by item description + length
        itemCount++;
    });

    // Debugging in case there's some unsupported types
    if (bufferOffset != BufLen) {
        console.error(`LOG ERROR buffer offset ${bufferOffset} does not match provided buffer length ${BufLen}!`);
        console.error(BufAddr.readByteArray(BufLen));
        console.error(formatStringItems);
        console.error(args[3].readCString());
    }

    return StringArg;
}

// Fake that all log types are enabled
const isEnabledFunc = Module.findExportByName('libsystem_trace.dylib', 'os_log_type_enabled');
Interceptor.attach(isEnabledFunc, {
  onLeave: function (ret) {
    ret.replace(1);
  }
});

// Hook all log levels and print them in different colors
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
        console.log(`\x1b[34m${printLog(args)}\x1b[0m`);  // print debug in blue
    },
});

Interceptor.attach(log_error, {
    onEnter: function (args) {
        console.error(printLog(args));
    },
});

console.log('PRINT ALL THE LOGS! \\o/');
