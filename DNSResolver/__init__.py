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
                qtype = DNSPacket.QTYPE[record[2].upper()]
                if qtype not in self.__cached_records:
                    self.__cached_records[qtype] = {}
                self.__cached_records[qtype][record[0]] = DNSPacket.DNSRecord(
                    record[0],
                    DNSPacket.QTYPE[record[2].upper()],
                    int(record[1]),
                    record[3],
                )
        for domain in root_srv_domains:
            self.__root_srv[IPVersion.IPV4].append(
                self.__check_cache(domain, DNSPacket.QTYPE.A).rdata
            )
            self.__root_srv[IPVersion.IPV6].append(
                self.__check_cache(domain, DNSPacket.QTYPE.AAAA).rdata
            )

    def __check_cache(
        self, domain: str, qtype: DNSPacket.QTYPE
    ) -> DNSPacket.DNSRecord | None:
        if qtype in self.__cached_records:
            if domain in self.__cached_records[qtype]:
                record: DNSPacket.DNSRecord = self.__cached_records[qtype][domain]
                if (
                    datetime.datetime.now() - record.creation_time
                ).seconds < record.ttl:
                    return record
                else:
                    self.__cached_records[qtype].pop(domain)
        return None

    def send_query(
        self, domain: str, qtype: DNSPacket.QTYPE, servers: list[str] = []
    ) -> DNSPacket.DNSPacket | None:
        dnsheader = DNSPacket.DNSHeader()
        dnsquestion = DNSPacket.DNSQuestion(domain, qtype)
        dnspacket = DNSPacket.DNSPacket(dnsheader, [dnsquestion], [], [], [])
        request_data = dnspacket.toBytes()
        if len(servers) == 0:
            servers = self.__root_srv[IPVersion.IPV4]
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        for server in servers:
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
