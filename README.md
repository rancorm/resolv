# resolv

Modern DNS lookup utility

## Usage

```
Usage: resolv <domain> <record>
```

```sh
resolv cormier.co mx
```

There are aliases for common records (e.g. DMARC, SIP, etc.), and for simplifying
commands, MAIL for MX for example.

```sh
resolv cormier.co dmarc
```

Aliases will be formed based on necessity.
