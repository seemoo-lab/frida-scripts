# Frida scripts

Collection of Frida scripts that turned out to be helpful for reverse-engineering :)

* [libdispatch.js](scripts/libdispatch.js) hooks iOS Grand Central Dispatch (GCD).
  This is useful to show thread creation. When printing a backtrace, you can even get an idea of
  the overall program flow. Prints might be out of order on high load, i.e., when attaching it
  to `CommCenter`, but it works quite well. Tested on iOS 13.3-14.4.