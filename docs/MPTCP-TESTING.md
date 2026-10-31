# MPTCP testing and security boundary

EdgeAegis is an HTTP-layer SecLang WAF. It does not inspect MPTCP protocol options, connection keys, subflow state or kernel reassembly. It cannot, by itself, mitigate MPTCP vulnerabilities in an operating system or network ingress.

For authorized testing, deploy an isolated Linux MPTCP-capable ingress ahead of EdgeAegis and verify:

1. The client and ingress negotiate MPTCP (not TCP fallback), using Linux TCP_IS_MPTCP (socket option 43).
2. Benign HTTP requests pass through EdgeAegis to the configured origin.
3. A benignly simulated WAF-triggering HTTP request is rejected by EdgeAegis before reaching the origin.
4. Origin logs confirm rejected requests never arrive.
5. MPTCP subflow and protocol-level vulnerability tests are conducted separately against a patched kernel in a disposable lab.

Do not interpret successful HTTP blocking as a fix for MPTCP kernel-level CVEs. Linux MPTCP sockets use IPPROTO_MPTCP (262); TCP_IS_MPTCP provides a way to detect negotiated MPTCP where supported. Older Linux kernels might not expose this option. Never treat a successful TCP fallback as verified MPTCP coverage.

For a named CVE, specify the affected kernel/version and exact vulnerability mechanism before claiming mitigation. Avoid production fault injection.
