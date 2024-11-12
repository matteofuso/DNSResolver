from enum import Enum
import DNSResolver.DNSPacket as DNSPacket
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
        print(self.__root_srv)

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
            self.__root_srv[IPVersion.IPV4] + self.__check_cache(domain, DNSPacket.QTYPE.A)
            # self.__root_srv[IPVersion.IPV6].append(
            #     [
            #         self.__get_values(record)
            #         for record in self.__check_cache(domain, DNSPacket.QTYPE.AAAA)
            #     ]
            # )

    def __cache_records(self, records: list[DNSPacket.DNSRecord]) -> None:
        for record in records:
            if record.qtype not in self.__cached_records:
                self.__cached_records[record.qtype] = {}
            sanitized_name = record.name.lower().strip(".") + "."
            if sanitized_name not in self.__cached_records[record.qtype]:
                self.__cached_records[record.qtype][sanitized_name] = []
            self.__cached_records[record.qtype][record.name].append(record)

    def __check_cache(
        self, fqdn: str, qtype: DNSPacket.QTYPE
    ) -> list[DNSPacket.DNSRecord] | None:
        sanitized_name = fqdn.lower().strip(".") + "."
        if qtype in self.__cached_records:
            if sanitized_name in self.__cached_records[qtype]:
                return self.__cached_records[qtype][fqdn]
        return None

    def __get_values(self, records: list[DNSPacket.DNSRecord]) -> list[str]:
        return [record.rdata for record in records]

    def send_query(
        self,
        domain: str,
        qtype: DNSPacket.QTYPE,
        servers: list[str] = [],
        rd: DNSPacket.RD = DNSPacket.RD.NO_RECURSION,
    ) -> DNSPacket.DNSPacket | None:
        dnsheader = DNSPacket.DNSHeader(rd=rd)
        dnsquestion = DNSPacket.DNSQuestion(domain, qtype)
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
        cache = self.__check_cache(fqdn, qtype)
        if cache:
            return cache
        servers = self.__root_srv[IPVersion.IPV4]
        while servers != []:
            print(servers)
            response = self.send_query(fqdn, qtype, servers)
            self.__cache_records(response.answer_records)
            self.__cache_records(response.authority_records)
            self.__cache_records(response.additional_records)
            if not response or response.header.rcode != DNSPacket.RCODE.NO_ERROR:
                return None
            if response.header.ancount > 0:
                return response
            servers = [
                self.__get_values(self.__check_cache(record.rdata, DNSPacket.QTYPE.A))
                for record in response.authority_records
            ]
            print(servers)
        return None
