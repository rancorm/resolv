# resolv

Modern DNS lookup utility

## Usage

Just pass the `domain` you want to lookup and you're in business.

```
Usage: resolv [-h -help] [-arpa] [-records] [-ratings] [-server <addr>] <domain> [record | alias]
```

Lookup mail (MX) records.

```sh
resolv cormier.co mx
```

There are aliases for common records (e.g. DMARC, SIP, etc.), and for simplifying
commands, MAIL for MX for example.

```sh
resolv cormier.co dmarc
```

Aliases will be formed based on necessity.

## More

List supported records and aliases.

```sh
resolv -records
```

The lesser done reverse lookup.

```sh
resolv -arpa 8.8.4.4
```
