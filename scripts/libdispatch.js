/*
 Grand Central Dispatch (GCD) is provided by libdispatch. It represents threads within
 a process on iOS. For example, `dispatch_async(queue, block)` takes a dispatch queue
 with a name and a block that defines execution including a function.

 Since even our debug prints are threaded, prints can occur out of order,
 so we have to combine them into one logging statement.
 
 libdispatch is open-sourced by Apple: https://opensource.apple.com/tarballs/libdispatch/


 Usage:

    * Attach to existing daemon
        frida -U your_target --no-pause -l libdispatch.js

    * Start with new daemon
        frida -U -f /bin/your_target --no-pause -l libdispatch.js

*/


/*
 libdispatch helper functions
*/

// Print the NSStackBlock function we're going to invoke.

function print_block_invoke(dispatch_block) {
    // Is at offset 0x10. Only the least significant are relevant.
    return `Callback function: ${DebugSymbol.fromAddress(dispatch_block.add(0x10).readPointer())}\n`;
}

// Get name of a queue
const _dispatch_queue_get_label_addr = Module.getExportByName('libdispatch.dylib', 'dispatch_queue_get_label');
const _dispatch_queue_get_label = new NativeFunction(_dispatch_queue_get_label_addr, "pointer", ["pointer"]);
function print_queue_label(dispatch_queue) {
    return `Calling queue: ${_dispatch_queue_get_label(dispatch_queue).readUtf8String()}\n`;
}

function print_backtrace(ctx) {
        return 'Backtrace:\n' +
            Thread.backtrace(ctx, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join('\n') + '\n';
}

// Hook async dispatching. We do the backtrace in the thread *before* dispatch_async
// was called, so we're off by one.
const _dispatch_async_addr = Module.getExportByName('libdispatch.dylib', 'dispatch_async');
Interceptor.attach(_dispatch_async_addr, {
    onEnter: function(args) {
        console.log('dispatch_async\n' +
            print_queue_label(args[0]) +
            print_block_invoke(args[1]) +
            print_backtrace(this.context));
    },
});

// Dispatching sync. Used a lot during service creation.
const _dispatch_sync_addr = Module.getExportByName('libdispatch.dylib', 'dispatch_sync');
Interceptor.attach(_dispatch_sync_addr, {
    onEnter: function(args) {
        console.log('dispatch_sync\n' +
            print_queue_label(args[0]) + 
            print_block_invoke(args[1]) +
            print_backtrace(this.context));
    },
});

// Dispatch queue creation
const _dispatch_queue_create_addr = Module.getExportByName('libdispatch.dylib', 'dispatch_queue_create');
Interceptor.attach(_dispatch_queue_create_addr, {
    onEnter: function(args) {
        console.log('dispatch_queue_create\n' +
    	    'Label: ' + args[0].readUtf8String() + '\n' +
    	    print_backtrace(this.context));;
    },
});

// Hook time dispatching, but this only gives time constraints so it shouldn't be relevant for us.
const _dispatch_time_addr = Module.getExportByName('libdispatch.dylib', 'dispatch_time');
Interceptor.attach(_dispatch_time_addr, {
    onEnter: function(args) {
        console.log('dispatch_time\n');
    },
});

// Delayed dispatching
const _dispatch_after_addr = Module.getExportByName('libdispatch.dylib', 'dispatch_after');
Interceptor.attach(_dispatch_after_addr, {
    onEnter: function(args) {
        console.log('dispatch_after\n' +
            //'in ' + args[0].readDouble() + 'ms' + 
            print_queue_label(args[1]) + 
            print_block_invoke(args[2]) +
            print_backtrace(this.context));
    },
}); 

/*
// hooking this leads to freezing the target process, hence it's disabled...
const _dispatch_once_addr = Module.getExportByName('libdispatch.dylib', 'dispatch_once');
Interceptor.attach(_dispatch_once_addr, {
    onEnter: function(args) {
        console.log('dispatch_once\n' +
            print_block_invoke(args[1]) +
            print_backtrace(this.context));
    },
});
*/