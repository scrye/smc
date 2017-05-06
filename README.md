# smc
Secure Multipath Communication Protocols

## Install
Download the patched MultipathTCP kernel from https://github.com/scrye/mptcp.

Compile the kernel with MPTCP support and the fullmesh path manager.

The following headers have changed and need to be copied in the include path:
* `include/asm-generic/poll.h`
* `include/linux/tcp.h`
* `include/x86_64-linux-gnu/bits/poll.h`

## Testing environment

The connection between client and server must have exactly two subflows (including the master subflow). Between a single pair of IP addresses you can configure the **mptcp_fullmesh** path manager on the client machine to open two subflows:

```bash
 echo '2' > /sys/module/mptcp_fullmesh/parameters/num_subflows
```

## Running the tests
Build the binaries using `make`.

`apps/client` connects to `apps/server` and downloads a single file, passed as argument, over an encrypted multipath connection. To run the test, first create a new file for transfer:
```bash
dd if=/dev/urandom of=smallfile.dat bs=1 count=512
```

Run `apps/server` on the Server machine:
```bash
LD_PRELOAD=../smkex/libsmkex.so ./server -i 0.0.0.0 -f smallfile.dat
```

Run `apps/client` on the Client machine, replacing `192.168.241.2` with the IP of the Server machine:
```bash
LD_PRELOAD=../smkex/libsmkex.so ./client -i 192.168.241.2 -p 1337 -f recv.dat
```
