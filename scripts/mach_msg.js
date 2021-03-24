/*
 Mach messages are used everywhere :) This script only prints them and doesn't do any
 deserialization. But it should be quite helpful to see how a target interacts with
 other system components and the kernel. Executables might use plain Mach messages, but
 usually, they call that via XPC, IOKit, etc.

 Might produce some out-of-order outputs on high load, be a bit careful with what you
 see and how you interpret it ;)

 Reconfigure how many bytes are printed and if XPC should be included.

 Since even our debug prints are threaded, prints can occur out of order.

 Usage:

    * Attach to existing daemon
        frida -U your_target --no-pause -l mach_msg.js

    * Start with new daemon
        frida -U -f /bin/your_target --no-pause -l mach_msg.js

*/

/*
 Configure options here!
*/
var mach_truncate_size = 0x100;
var mach_remove_xpc = false;



var _mach_msg_addr = Module.getExportByName('libSystem.B.dylib', 'mach_msg');

// Using some global variables here for onEnter vs. onLeave, works most of the time...
var _mach_msg_body_ptr;
var _mach_msg_rcv_size;
var _mach_msg_snd_size;
var _mach_is_xpc = false;


Interceptor.attach(_mach_msg_addr, {

    // parse what we send
    onEnter: function(args) {

        _mach_is_xpc = false;
        _mach_msg_body_ptr = args[0].add(0x18);
        if (mach_remove_xpc && _mach_msg_body_ptr.readU32() == 1079529539) { // Integer corresponding to "CPX@"
            console.log('  * mach_msg(XPC, skipping for perf)');
            _mach_is_xpc = true;
        } else {
            console.log('  * mach_msg(msg: ' + args[0] + ', option: ' + args[1] + ', send_size: ' +
                args[2] + ', rcv_size: ' + args[3] + ', rcv_name: ' + args[4] + '...)');

            // get send_size bytes of body
            _mach_msg_snd_size = parseInt(args[2]);
            if (_mach_msg_snd_size > 0 && _mach_msg_snd_size < mach_truncate_size) {
                console.log('           v---- mach_msg input ----');
                console.log(_mach_msg_body_ptr.readByteArray(_mach_msg_snd_size));
            } else if (_mach_msg_snd_size > 0) {
                console.log('           v---- mach_msg input (truncated) ----');
                console.log(_mach_msg_body_ptr.readByteArray(mach_truncate_size));
            }

            // keep receive_size info for later
            _mach_msg_rcv_size = parseInt(this.context.x3);
        }
    },

    // parse what we receive in response
    // as far as I understand the original mach_msg body is overwritten on return
    onLeave: function(r) {

        //console.log(r); // it's only 0x0 for success, not interesting to print

        if ( ! (mach_remove_xpc && _mach_is_xpc)) { // skip XPC messages if mach_remove_xpc=true and _mach_is_xpc=true

            if (_mach_msg_rcv_size > 0 && _mach_msg_rcv_size < mach_truncate_size) {
                console.log('           v---- mach_msg output ----');
                console.log(_mach_msg_body_ptr.readByteArray(_mach_msg_rcv_size));
            } else if (_mach_msg_rcv_size > 0) {
                console.log('           v---- mach_msg output (truncated) ----');
                console.log(_mach_msg_body_ptr.readByteArray(mach_truncate_size));
            }
        }
    }
});
