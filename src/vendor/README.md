# Apple PF ABI extract

`pf_abi.h` contains only the userspace structures/constants needed by `pf_anchor.c`,
extracted on 2026-11-08 from Apple's `bsd/net/pfvar.h`:
https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pfvar.h

The downloaded source's SHA256 is recorded in the header. Upstream copyright and
license notices are retained; `APPLE_LICENSE` is the corresponding upstream license.
Modifications: unused declarations and kernel-only dependencies were omitted, standard
SDK includes and a dedicated include guard were added. No external download is needed
at build/install time.

The macOS SDK does not ship this private PF header. Compile-time layout assertions and
a read-only ioctl before mutation catch incompatible layouts. There is deliberately no
fallback that reloads the root ruleset. `pf-anchor check` performs only the read check.
