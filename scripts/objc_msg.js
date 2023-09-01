/*
Prints all Objective-C calls (without arguments).
Huge performance impact, handle with care.
*/

const _objc_msgSend = Module.getExportByName(null, 'objc_msgSend');
Interceptor.attach(_objc_msgSend, {
    onEnter: function(args) {
        console.log(`objc_msgSend(${(new ObjC.Object(args[0])).$className}, ${args[1].readCString()})`);
    },
});

console.log('logging all objective-c calls...')