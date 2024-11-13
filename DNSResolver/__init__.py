from enum import Enum
import DNSResolver.DNSPacket as DNSPacket
import ipaddress
import datetime
import socket


class IPVersion(Enum):
    IPV4 = 4
    IPV6 = 6


class DNSResolver:
    def __init__(self):
        self.__root_srv = {IPVersion.IPV4: [], IPVersion.IPV6: []}
        self.__cached_records = {}
        self.__loadRootNS("named.root")

    def __loadRootNS(self, file: str) -> None:
        root_srv_domains = []
        with open(file, "r") as f:
            for line in f:
                if line.startswith(";") or line == "":
                    continue
                record = str.lower(line).split()
                if len(record) != 4:
                    continue
                if record[2] == "ns":
                    root_srv_domains.append(record[3])
                    continue
                self.__cache_records(
                    [
                        DNSPacket.DNSRecord(
                            record[0],
                            DNSPacket.QTYPE[record[2].upper()],
                            int(record[1]),
                            record[3],
                        )
                    ]
                )
        for domain in root_srv_domains:
            self.__root_srv[IPVersion.IPV4] += self.__check_cache(
                domain, DNSPacket.QTYPE.A
            ).answer_records
            self.__root_srv[IPVersion.IPV6] += self.__check_cache(
                domain, DNSPacket.QTYPE.AAAA
            ).answer_records

    def __sanitize_domain(self, domain: str) -> str:
        return domain.lower().strip(".") + "."

    def __cache_records(self, records: list[DNSPacket.DNSRecord]) -> None:
        for record in records:
            if record.qtype not in self.__cached_records:
                self.__cached_records[record.qtype] = {}
            sanitized_name = self.__sanitize_domain(record.name)
            if sanitized_name not in self.__cached_records[record.qtype]:
                self.__cached_records[record.qtype][sanitized_name] = []
            self.__cached_records[record.qtype][record.name].append(record)

    def __check_cache(
        self, fqdn: str, qtype: DNSPacket.QTYPE
    ) -> DNSPacket.DNSPacket | None:
        sanitized_name = self.__sanitize_domain(fqdn)
        if qtype in self.__cached_records:
            if sanitized_name in self.__cached_records[qtype]:
                return DNSPacket.DNSPacket(
                    answer_records=self.__cached_records[qtype][fqdn]
                )
        return None

    def send_query(
        self,
        fqdn: str,
        qtype: DNSPacket.QTYPE,
        servers: list[str] = [],
        rd: DNSPacket.RD = DNSPacket.RD.NO_RECURSION,
    ) -> DNSPacket.DNSPacket | None:
        dnsheader = DNSPacket.DNSHeader(rd=rd)
        dnsquestion = DNSPacket.DNSQuestion(self.__sanitize_domain(fqdn), qtype)
        dnspacket = DNSPacket.DNSPacket(dnsheader, [dnsquestion], [], [], [])
        request_data = dnspacket.toBytes()
        if len(servers) == 0:
            servers = self.__root_srv[IPVersion.IPV4]
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        for server in servers:
            if server == None or server == "":
                continue
            try:
                sock.sendto(request_data, (server, 53))
                buffer = b""
                while True:
                    data = sock.recv(1024)
                    buffer += data
                    if len(data) < 1024:
                        break
                sock.close()
                return DNSPacket.DNSPacket.fromBytes(buffer)
            except socket.timeout:
                continue
        sock.close()
        return None

    def recursive_query(
        self, fqdn: str, qtype: DNSPacket.QTYPE = DNSPacket.QTYPE.A
    ) -> DNSPacket.DNSPacket | None:
        fqdn = self.__sanitize_domain(fqdn)
        cache = self.__check_cache(fqdn, qtype)
        if cache:
            return cache
        servers = [server.rdata for server in self.__root_srv[IPVersion.IPV4]]
        split = fqdn.split(".")
        for i in range(len(split) - 2, 0, -1):
            domain = ".".join(split[i:])
            if not servers:
                return None
            response = self.__check_cache(domain, DNSPacket.QTYPE.NS)
            if not response:
                response = self.send_query(domain, DNSPacket.QTYPE.NS, servers)
            if not response:
                return None
            self.__cache_records(response.answer_records)
            self.__cache_records(response.authority_records)
            self.__cache_records(response.additional_records)
            if (
                response.header.rcode != DNSPacket.RCODE.NAME_ERROR
                and response.header.rcode != DNSPacket.RCODE.NO_ERROR
            ):
                return None
            servers = []
            for record in (
                response.answer_records
                + response.authority_records
                + response.additional_records
            ):
                if record.qtype == DNSPacket.QTYPE.NS:
                    ns_domain = record.rdata
                elif record.qtype == DNSPacket.QTYPE.SOA:
                    ns_domain = record.rdata.mname
                else:
                    continue
                records = self.recursive_query(
                    ns_domain, DNSPacket.QTYPE.A
                ).answer_records
                servers += [record.rdata for record in records]
                break
        return self.send_query(fqdn, qtype, servers)

    def reverse_lookup_v4(self, ipv4: str) -> DNSPacket.DNSPacket | None:
        return self.recursive_query(
            ".".join(ipv4.split(".")[::-1]) + ".in-addr.arpa",
            DNSPacket.QTYPE.PTR,
        )

    def reverse_lookup_v6(self, ipv6: str) -> DNSPacket.DNSPacket | None:
        decompressed = ipaddress.IPv6Address(ipv6).exploded
        return self.recursive_query(
            ".".join(decompressed.split(":")[::-1]) + ".ip6.arpa",
            DNSPacket.QTYPE.PTR,
        )
