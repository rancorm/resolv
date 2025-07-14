# resolv

Modern DNS lookup utility

## Build

To build the binary.

```sh
go build
```

## Usage

Pass the `domain` you want to lookup and you're in business. For a specific `record` type
include it after the domain. Common records are MX, SRV, SOA, A (default), AAAA, and 
many [more](https://en.wikipedia.org/wiki/List_of_DNS_record_types).

```
Usage: resolv [-h -help] [-arpa] [-records] [-ratings] [-s -server <addr>] <domain> [record | alias]
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

[Root servers](https://en.wikipedia.org/wiki/Root_name_server) lookup.

```sh
resolv . ns
NS .
code=0 num=13 rtt=20ms [very good]
-
h.root-servers.net [ttl=2600]
i.root-servers.net [ttl=2600]
j.root-servers.net [ttl=2600]
k.root-servers.net [ttl=2600]
l.root-servers.net [ttl=2600]
m.root-servers.net [ttl=2600]
a.root-servers.net [ttl=2600]
b.root-servers.net [ttl=2600]
c.root-servers.net [ttl=2600]
d.root-servers.net [ttl=2600]
e.root-servers.net [ttl=2600]
f.root-servers.net [ttl=2600]
g.root-servers.net [ttl=2600]
```

## More

List supported records and aliases.

```sh
resolv -records
```

The lesser done reverse lookup.

```sh
resolv -arpa 8.8.4.4
```
