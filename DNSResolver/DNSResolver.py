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
        self, fqdn: str, qtype: list[DNSPacket.QTYPE | str] = DNSPacket.QTYPE.A
    ) -> DNSPacket.DNSPacket | None:
        
        def get_ns_address(ns_list: list[str]) -> list[str]:
            addresses = []
            for ns in ns_list:
                ns_address = self.__check_cache(ns.rdata, DNSPacket.QTYPE.A)
                if ns_address:
                    addresses += [server.rdata for server in ns_address]
            if not addresses:
                for ns in ns_list:
                    ns_address = self.recursive_query(ns.rdata, DNSPacket.QTYPE.A)
                    if ns_address:
                        addresses += [server.rdata for server in ns_address.answer_records]
                    if len(addresses) == 1:
                        break
            return addresses
        
        if type(qtype) == str:
            try:
                qtype = DNSPacket.QTYPE[qtype.upper()]
            except KeyError:
                return None
        if fqdn == "":
            return None
        fqdn = self.__sanitize_domain(fqdn)
        cache = self.__check_cache(fqdn, qtype)
        if cache:
            return DNSPacket.DNSPacket(
                header=DNSPacket.DNSHeader(qr=DNSPacket.QR.RESPONSE),
                answer_records=cache,
            )
        servers = []
        nearest_ns = self.__check_nearest_ns(fqdn)
        if nearest_ns:
            servers = get_ns_address(nearest_ns)
        else:
            servers = [server.rdata for server in self.__root_srv[IPVersion.IPV4]]
        while servers:
            response = self.send_query(fqdn, qtype, servers)
            if not response:
                return None
            if response.header.rcode != DNSPacket.RCODE.NO_ERROR:
                return response
            self.__cache_records(response.answer_records)
            self.__cache_records(response.authority_records)
            self.__cache_records(response.additional_records)
            if response.header.ancount > 0:
                return response
            ns_list = []
            for record in response.authority_records + response.additional_records:
                if record.qtype == DNSPacket.QTYPE.NS:
                    ns_list.append(record)
                elif record.qtype == DNSPacket.QTYPE.SOA:
                    ns_list.append(record.rdata.mname)
                else:
                    continue
            servers = get_ns_address(ns_list)

    def reverse_lookup_v4(self, ipv4: str) -> DNSPacket.DNSPacket | None:
        try:
            ipaddress.IPv4Address(ipv4)
        except ipaddress.AddressValueError:
            return None
        return self.recursive_query(
            ".".join(ipv4.split(".")[::-1]) + ".in-addr.arpa",
            DNSPacket.QTYPE.PTR,
        )

    def reverse_lookup_v6(self, ipv6: str) -> DNSPacket.DNSPacket | None:
        try:
            decompressed = ipaddress.IPv6Address(ipv6).exploded
        except ipaddress.AddressValueError:
            return None
        return self.recursive_query(
            ".".join(list(decompressed.replace(":", ""))[::-1]) + ".ip6.arpa",
            DNSPacket.QTYPE.PTR,
        )
