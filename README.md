The program functions as a basic router which incorporates ARP cache as
well as IP forwarding. The general design was done by following the 
procedure as described in the discussion slides as well as with a lot of
help from piazza posts.

I started with the handle\_packet() function inside of the sr\_router.c file
and began by implementing the functionality of ARP request. Following that,
I worked on the implementation of ARP reply. These parts ended up being
significantly easier than the rest of the project which was the entirety
of IP.

After I finished up the IP part of handle\_packet(), I moved on to
the handle\_arpreq helper function in sr\arpcahce.c. I'm not sure I handled
it correctly. What I do is call the pthread\_mutex\_lock() function on the
cache lock before I call handle\_arpreq() and unlock it afterwards. Doing
so, I had to create an entirely new sr\_arpreq\_destroy() function that
does not pthread\_mutex lock/unlock the cache lock in order to avoid double
locking/unlocking the cache lock inside of the handle\_arpreq() function.

Another issue I seem to be having is the latency. My ping times (ms) and
traceroutes are signficantly slower than the solution. This suggests some
part of my implementation is faulty. I have the ARP request resent every
second.

One of the design decisions I regret making is for how I implement the ICMP
packets. I would of saved myself a lot of pain if I made a separate 
function for creating the ICMP packets instead of copy-pasting my code
over and over again for all five of them. Now I have a lot of redundant
code that I could of avoided which could partially of helped me make the
initial turnin time. I guess it can't be helped.
