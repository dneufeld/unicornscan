THIS CODE BASE is not intented to be secure 

honestly, though, lets expand on this a bit, seeing as how that can
be a confusing statement.
the following things are true about this codebase:
 1) this is not a product. this is a pre-1.0 version of a GPL tool.
 2) there is no formal security review of this code at this time.
 3) if you have concerns about this code mis-behaving then you should
  a) use selinux and work with the policy, however you should note that
   1) if the listener is compromised, the attacker has a raw socket to read from. this may or maynot
   be a problem, depending on how you run it. so some thought should be put into _where_ you are running
   this code. if you really use this tool perhaps you should read though the policy. the chroot setuid
   protection in the non-selinux code doesnt really give you enough protection imo.
  b) review the code, this release is for developers and interested people to _play_ with. If you find
  anything you dont like we would love to hear from you.
 4) the rate of development right now and the state of it is _not_ stable, think of this being a CVS
 checkout of code. If it breaks im not going to cry. Ill try and do a decent job right now, but i think
 you should fully understand where the state of this project is before you use it.

BEFORE YOU TYPE MAKE,
1) run ./configure --help and read it
2) run ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --enable-bundled-ltdl for example
3) type make
4) type make install

have fun, be good, and please talk to us.
#unicornscan on efnet.
https://lists.sourceforge.net/lists/listinfo/osace-users
