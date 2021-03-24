/*
 Grand Central Dispatch (GCD) is provided by libdispatch. It represents threads within
 a process on iOS. For example, `dispatch_async(queue, block)` takes a dispatch queue
 with a name and a block that defines execution including a function.

 Since even our debug prints are threaded, prints can occur out of order.
 
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
    console.log('Callback function: ' + DebugSymbol.fromAddress(dispatch_block.add(0x10).readPointer()));
}

// Get name of a queue
var _dispatch_queue_get_label_addr = Module.getExportByName('libdispatch.dylib', 'dispatch_queue_get_label');
var _dispatch_queue_get_label = new NativeFunction(this._dispatch_queue_get_label_addr, "pointer", ["pointer"]);
function print_queue_label(dispatch_queue) {
    console.log('Calling queue: ' + _dispatch_queue_get_label(dispatch_queue).readUtf8String());
}

function print_backtrace(ctx) {
        console.log('Backtrace:\n' +
        Thread.backtrace(ctx, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress).join('\n') + '\n');
}

/*
 Hook async dispatching. We do the backtrace in the thread *before* dispatch_async
 was called, so we're off by one.
*/
var _dispatch_async_addr = Module.getExportByName('libdispatch.dylib', 'dispatch_async');
Interceptor.attach(_dispatch_async_addr, {
    onEnter: function() {
        console.log('dispatch_async');
        print_queue_label(this.context.x0);
    	print_block_invoke(this.context.x1);
    	print_backtrace(this.context);
    },
});

/*
 Dispatching sync. Used a lot during service creation.
*/
var _dispatch_sync_addr = Module.getExportByName('libdispatch.dylib', 'dispatch_sync');
Interceptor.attach(_dispatch_sync_addr, {
    onEnter: function() {
        console.log('dispatch_sync');
        print_queue_label(this.context.x0);
    	print_block_invoke(this.context.x1);
        print_backtrace(this.context);
    },
});

/*
 Dispatch queue creation
*/
var _dispatch_queue_create_addr = Module.getExportByName('libdispatch.dylib', 'dispatch_queue_create');
Interceptor.attach(_dispatch_queue_create_addr, {
    onEnter: function() {
        console.log('dispatch_queue_create');
    	console.log('Label: ' + this.context.x0.readUtf8String());
    	print_backtrace(this.context);
    },
});

/*
 Hook time dispatching, but this only gives time constraints so it shouldn't be relevant for us.
*/
var _dispatch_time_addr = Module.getExportByName('libdispatch.dylib', 'dispatch_time');
Interceptor.attach(_dispatch_time_addr, {
    onEnter: function() {
        console.log('dispatch_time');
    },
});


/*
 Dispatching after a given time. It's defined as 64bit ENUM with 0=now and max=forever,
 but depends on the *OS version. Results in a Frida error :(
*/
/*
var _dispatch_after_addr = Module.getExportByName('libdispatch.dylib', 'dispatch_after');
Interceptor.attach(_dispatch_after_addr, {
    onEnter: function(t, q, b) {
        console.log('!!!!!!!!!!!!!! dispatch_after');
        //console.log("Time: " + this.context.x0.readDouble());
        //print_queue_label(this.context.x1);
    	//print_block_invoke(this.context.x2);
    	//print_backtrace(this.context);
    },
});
*/

/*
 Dispatching once. Results in a Frida error :(
*/
/*
var _dispatch_once_addr = Module.getExportByName('libdispatch.dylib', 'dispatch_once');
Interceptor.attach(_dispatch_once_addr, {
    onEnter: function(q, b) {
        console.log('dispatch_once');
    	//print_block_invoke(this.context.x1);
        //print_backtrace(this.context);
    },
});
*/