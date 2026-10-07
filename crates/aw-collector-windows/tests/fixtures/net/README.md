# Hand-written Kernel-Network and DNS-Client fixtures

These files are not an ETW recording. SPIKE-02 was not run elevated, and the
machine that produced them was not an administrator, so there is no captured
session to put here. Each line uses the property names from windows.md §2.3
(network) and §2.4 (DNS). A property the line omits is absent: the decoder
marks it `NA(collector_unavailable)` and does not invent a zero.

Addresses are dotted or colon text, not the binary layout ETW would use. The
test parses them before calling the decoder. That parse is part of the fixture
reader, not a claim about the on-wire type.
