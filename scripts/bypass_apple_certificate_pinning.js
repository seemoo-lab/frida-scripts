// global TLS certificate pinning bypass, also works on Apple's domains
//
// frida -U trustd --load bypass_apple_certificate_pinning.js


// just tell we're using a different domain that's not pinned
const domain = ObjC.classes.NSString.alloc().initWithString_("google.com")

const queryForDomain = ObjC.classes.SecPinningDb['- queryForDomain:'].implementation
Interceptor.attach(queryForDomain, {
    onEnter(args) {
        let oldDomain = new ObjC.Object(args[2])
        console.log(`-[SecPinningDb queryForDomain:${oldDomain}] -- replacing with new domain to bypass pinning`)
        args[2] = domain
    }
});

console.log("ready!")