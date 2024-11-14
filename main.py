import DNSResolver

res = DNSResolver.DNSResolver()
#a = res.recursive_query("riejgio.ocmoemr.com.", DNSResolver.DNSPacket.QTYPE.A)
#a = res.reverse_lookup_v4("151.49.200.58")
#a = res.reverse_lookup_v6("2606:4700:4700::1111")
a = res.send_query("1.1.1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.4.0.0.7.4.6.0.6.2.ip6.arpa.", DNSResolver.DNSPacket.QTYPE.PTR, ["198.41.0.4"])
print(a)