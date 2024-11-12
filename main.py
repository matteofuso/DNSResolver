import DNSResolver

res = DNSResolver.DNSResolver()
a = res.recursive_query("mail.google.com", DNSResolver.DNSPacket.QTYPE.A)
print(a)