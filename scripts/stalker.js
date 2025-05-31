console.log("loading");

const f = Module.getGlobalExportByName('open');

Interceptor.attach(f, {
    onEnter: function(args) {
        console.log('entered function');
        Stalker.follow({ 
            events: {
                // only collect coverage for newly encountered blocks
                compile: true,
		//call: true,
            },
            onReceive: function (events) {
                const bbs = Stalker.parse(events, {
                    stringify: false,
                    annotate: false
                });
                console.log("Stalker trace: \n" + bbs.flat().map(DebugSymbol.fromAddress).join('\n'));
            }
        });
    },
    onLeave: function(retval) {
        Stalker.unfollow();
        Stalker.flush();  // this is important to get all events  
    }
});


console.log("loaded");
