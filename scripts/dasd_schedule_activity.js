/// <reference path="frida-gum.d.ts" />

// Usage:
// frida [-U] dasd --load dasd_schedule_activity.js
// Then trigger an activity...
//
// https://bryce.co/running-xpc-activities-on-demand/

// +[_DASDaemon sharedInstance]
var sharedInstance = ObjC.classes._DASDaemon.sharedInstance();
sharedInstance = new ObjC.Object(sharedInstance);
console.log("Got DASDaemon instance: " + sharedInstance);

function run_activity(activity_name) {
    const {NSString, NSArray} = ObjC.classes;
    const activity_string = NSString['stringWithString:'](activity_name);
    const activity_array = NSArray.alloc().initWithObject_(activity_string);

    sharedInstance.forceRunActivities_(activity_array);
    console.log("ran activity");
}

//run_activity("com.apple.CacheDelete.daily");
console.log("Now call e.g. `run_activity('com.apple.CacheDelete.daily')`");
