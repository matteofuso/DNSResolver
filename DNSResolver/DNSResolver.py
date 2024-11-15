from enum import Enum
from DNSResolver import DNSPacket
import ipaddress
import socket


class IPVersion(Enum):
    IPV4 = 4
    IPV6 = 6


class DNSResolver:
    def __init__(self, root_file: str = "named.root") -> None:
        self.__root_srv = {IPVersion.IPV4: [], IPVersion.IPV6: []}
        self.__cached_records = {}
        self.__loadRootNS(root_file)

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
            )
            self.__root_srv[IPVersion.IPV6] += self.__check_cache(
                domain, DNSPacket.QTYPE.AAAA
            )

    def __sanitize_domain(self, domain: str) -> str:
        return domain.lower().strip(".") + "."

    def __cache_records(self, packet: list[DNSPacket.DNSRecord]) -> None:
        for record in packet:
            sanitized_name = self.__sanitize_domain(record.name)
            if sanitized_name not in self.__cached_records:
                self.__cached_records[sanitized_name] = {}
            if record.qtype not in self.__cached_records[sanitized_name]:
                self.__cached_records[sanitized_name][record.qtype] = []
            if record not in self.__cached_records[sanitized_name][record.qtype]:
                self.__cached_records[sanitized_name][record.qtype].append(record)

    def __check_cache(
        self, fqdn: str, qtype: DNSPacket.QTYPE
    ) -> list[DNSPacket.DNSRecord] | None:
        sanitized_name = self.__sanitize_domain(fqdn)
        if sanitized_name in self.__cached_records:
            if qtype in self.__cached_records[sanitized_name]:
                return self.__cached_records[sanitized_name][qtype]
        return None

    def __check_nearest_ns(self, fqdn: str) -> list[DNSPacket.DNSRecord] | None:
        sanitized_name = self.__sanitize_domain(fqdn)
        split = sanitized_name.split(".")
        for i in range(len(split)):
            nearest_ns = self.__check_cache(".".join(split[i:]), DNSPacket.QTYPE.NS)
            if nearest_ns:
                return nearest_ns

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
        sock.settimeout(1)
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
        self,
        fqdn: str,
        qtype: DNSPacket.QTYPE = DNSPacket.QTYPE.A,
        recursion_limit: int = 10,
        recursion_count: int = 0,
    ) -> DNSPacket.DNSPacket | None:
        if recursion_count >= recursion_limit:
            return None
        fqdn = self.__sanitize_domain(fqdn)
        cache = self.__check_cache(fqdn, qtype)
        if cache:
            return DNSPacket.DNSPacket(answer_records=cache)
        servers = []
        nearest_ns = self.__check_nearest_ns(fqdn)
        if not nearest_ns:
            servers = [server.rdata for server in self.__root_srv[IPVersion.IPV4]]
        else:
            for ns in nearest_ns:
                server = self.__check_cache(ns.rdata, DNSPacket.QTYPE.A)
                if server:
                    servers += [server.rdata for server in server]
            if not servers:
                for ns in nearest_ns:
                    records = self.recursive_query(
                        ns, DNSPacket.QTYPE.A, recursion_limit, recursion_count + 1
                    ).answer_records
                    if records:
                        servers += [server.rdata for server in records]
                        break

        while servers:
            response = self.send_query(fqdn, qtype, servers)
            if not response:
                return None
            if response.header.rcode != DNSPacket.RCODE.NO_ERROR:
                return None
            self.__cache_records(response.answer_records)
            self.__cache_records(response.authority_records)
            self.__cache_records(response.additional_records)
            if response.header.ancount > 0:
                return response
            servers = []
            ns_list = []
            for record in response.authority_records + response.additional_records:
                if record.qtype == DNSPacket.QTYPE.NS:
                    ns_list.append(record.rdata)
                elif record.qtype == DNSPacket.QTYPE.SOA:
                    ns_list.append(record.rdata.mname)
                else:
                    continue
            if len(ns_list) == 0:
                return None
            for ns_domain in ns_list:
                records = self.__check_cache(ns_domain, DNSPacket.QTYPE.A)
                if records:
                    servers += [server.rdata for server in records]
            if servers:
                continue
            for ns_domain in ns_list:
                records = self.recursive_query(
                    ns_domain, DNSPacket.QTYPE.A, recursion_limit, recursion_count + 1
                ).answer_records
                if records:
                    servers += [server.rdata for server in records]
                    break
        return None

    def reverse_lookup_v4(self, ipv4: str) -> DNSPacket.DNSPacket | None:
        return self.recursive_query(
            ".".join(ipv4.split(".")[::-1]) + ".in-addr.arpa",
            DNSPacket.QTYPE.PTR,
        )

    def reverse_lookup_v6(self, ipv6: str) -> DNSPacket.DNSPacket | None:
        decompressed = ipaddress.IPv6Address(ipv6).exploded
        return self.recursive_query(
            ".".join(list(decompressed.replace(":", ""))[::-1]) + ".ip6.arpa",
            DNSPacket.QTYPE.PTR,
        )
