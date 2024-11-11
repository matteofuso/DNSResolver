import DNSResolver

resolver = DNSResolver.DNSResolver()
print(
    resolver.send_query(
        "58.200.49.151.in-addr.arpa", DNSResolver.DNSPacket.QTYPE.PTR, ["192.106.1.1"]
    )
)
