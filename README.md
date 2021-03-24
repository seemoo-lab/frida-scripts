# Frida Scripts

Collection of Frida scripts that turned out to be helpful for reverse-engineering :)
The goal of these scripts is to be rather generic and provide you with insights about 
larger closed-source projects.

## iOS

* [libdispatch.js](scripts/libdispatch.js) hooks iOS Grand Central Dispatch (GCD).
  This is useful to show thread creation. When printing a backtrace, you can even get an idea of
  the overall program flow. Prints might be out of order on high load, i.e., when attaching it
  to `CommCenter`, but it works quite well. Tested on iOS 13.3-14.4.
  
  
* [mach_msg.js](scripts/mach_msg.js) hooks iOS Mach messages.
  Almost everything is a Mach message on iOS, from Cross-Process Communication (XPC) to
  IOKit driver calls in the kernel. Might be a bit verbose, tunable via two parameters to
  truncate messages and skip XPC. Tested on iOS 13.3-14.4.