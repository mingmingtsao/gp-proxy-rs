# Security reports

Please use [GitHub private vulnerability reporting](https://github.com/mingmingtsao/gp-proxy-rs/security/advisories/new)
for vulnerabilities, especially authentication, proxy bypass or credential exposure.
Include the affected commit, platform and a minimal synthetic reproducer.

Do not submit real passwords, cookies, `.env` files, private CA keys, gateway
response bodies or production packet captures. Ordinary bugs belong in Issues;
replace internal hostnames and addresses before sharing diagnostics.

The proxy listens only on loopback and has no local client authentication.
Use it on a trusted personal workstation. Corporate requests have no host-network
fallback, but applications must actually honor their proxy configuration.
