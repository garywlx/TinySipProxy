# Tiny SIP Proxy

A very simple SIP proxy. This is mainly intended as a base for programs
that manipulate or monitor SIP requests and responses.

The **ping** branch contains an example that responds to Ping requests
without forwarding them.

## Compiling

```sh
make
```

### OpenWRT package

```sh
make openwrt OPENWRT_SDK_TARBALL=/path/to/openwrt-sdk-….tar.xz
```
