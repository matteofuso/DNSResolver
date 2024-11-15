from enum import Enum
import struct
import datetime
import ipaddress


class QR(Enum):
    QUERY = 0
    RESPONSE = 1


class OPCODE(Enum):
    QUERY = 0
    IQUERY = 1
    STATUS = 2


class AA(Enum):
    NOT_AUTHORITATIVE = 0
    AUTHORITATIVE = 1


class TC(Enum):
    NOT_TRUNCATED = 0
    TRUNCATED = 1


class RD(Enum):
    NO_RECURSION = 0
    RECURSION = 1


class RA(Enum):
    NO_RECURSION_AVAILABLE = 0
    RECURSION_AVAILABLE = 1


class Z(Enum):
    RESERVED = 0


class AD(Enum):
    NOT_AUTHENTICATED = 0
    AUTHENTICATED = 1


class CD(Enum):
    NO_CHECK = 0
    CHECK = 1


class RCODE(Enum):
    NO_ERROR = 0
    FORMAT_ERROR = 1
    SERVER_FAILURE = 2
    NAME_ERROR = 3
    NOT_IMPLEMENTED = 4
    REFUSED = 5


class QTYPE(Enum):
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    AAAA = 28


class QCLASS(Enum):
    IN = 1


class DNSComponent:
    def toBytes(self) -> bytes:
        pass

    def fromBytes(self, data: bytes) -> "DNSComponent":
        pass

    def __str__(self) -> str:
        pass

    def __repr__(self) -> str:
        pass

    def __eq__(self, value: object) -> bool:
        pass

    def _nameToBytes(name: str) -> bytes:
        bytes_name = b""
        for part in name.split("."):
            bytes_name += len(part).to_bytes(1, "big") + part.encode()
        return bytes_name

    def _readNameFromBytes(full_data, offset, limitBytes=-1) -> tuple[str, int]:
        name = ""
        start_offset = 0
        while full_data[offset + start_offset] != 0 and (
            limitBytes == -1 or start_offset < limitBytes
        ):
            lenght = full_data[offset + start_offset]
            start_offset += 1
            if lenght == 0xC0:
                ptr_name, _ = DNSComponent._readNameFromBytes(
                    full_data, full_data[offset + start_offset]
                )
                name += ptr_name
                break
            else:
                name += (
                    full_data[
                        offset + start_offset : offset + start_offset + lenght
                    ].decode()
                    + "."
                )
                start_offset += lenght
        start_offset += 1
        return name, start_offset


class DNSHeader(DNSComponent):
    # https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
    # https://datatracker.ietf.org/doc/html/rfc2535#section-6.1
    def __init__(
        self,
        id: int = 0,
        qr: QR = QR.QUERY,
        opcode: OPCODE = OPCODE.QUERY,
        aa: AA = AA.NOT_AUTHORITATIVE,
        tc: TC = TC.NOT_TRUNCATED,
        rd: RD = RD.NO_RECURSION,
        ra: RA = RA.NO_RECURSION_AVAILABLE,
        z: Z = Z.RESERVED,
        ad: AD = AD.NOT_AUTHENTICATED,
        cd: CD = CD.NO_CHECK,
        rcode: RCODE = RCODE.NO_ERROR,
        qdcount: int = 0,
        ancount: int = 0,
        nscount: int = 0,
        arcount: int = 0,
    ) -> None:
        self.id = id
        self.qr = qr
        self.opcode = opcode
        self.aa = aa
        self.tc = tc
        self.rd = rd
        self.ra = ra
        self.z = z
        self.ad = ad
        self.cd = cd
        self.rcode = rcode
        self.qdcount = qdcount
        self.ancount = ancount
        self.nscount = nscount
        self.arcount = arcount

    def toBytes(self) -> bytes:
        return struct.pack(
            ">HHHHHH",
            self.id,
            (self.qr.value << 15)
            | (self.opcode.value << 11)
            | (self.aa.value << 10)
            | (self.tc.value << 9)
            | (self.rd.value << 8)
            | (self.ra.value << 7)
            | (self.z.value << 6)
            | (self.ad.value << 5)
            | (self.cd.value << 4)
            | self.rcode.value,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        )

    def fromBytes(full_data: bytes) -> "DNSHeader":
        id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
            ">HHHHHH", full_data[:12]
        )
        qr = QR((flags & 0b1000000000000000) >> 15)
        opcode = OPCODE((flags & 0b0111100000000000) >> 11)
        aa = AA((flags & 0b0000010000000000) >> 10)
        tc = TC((flags & 0b0000001000000000) >> 9)
        rd = RD((flags & 0b0000000100000000) >> 8)
        ra = RA((flags & 0b0000000010000000) >> 7)
        z = Z((flags & 0b0000000001110000) >> 6)
        ad = AD((flags & 0b0000000000001000) >> 5)
        cd = CD((flags & 0b0000000000000100) >> 4)
        rcode = RCODE(flags & 0b0000000000001111)
        return DNSHeader(
            id,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            z,
            ad,
            cd,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        )

    def __str__(self) -> str:
        return f"Header: opcode: {self.opcode}, status: {self.rcode}, id: {self.id}\
            \nflags: {self.qr} {self.aa} {self.tc} {self.rd} {self.ra} {self.ad} {self.cd}\
            \nAnswer: {self.ancount}, Authority: {self.nscount}, Additional: {self.arcount}"

    def __repr__(self) -> str:
        return self.__str__()

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, DNSHeader):
            return False
        return (
            self.id == value.id
            and self.qr == value.qr
            and self.opcode == value.opcode
            and self.aa == value.aa
            and self.tc == value.tc
            and self.rd == value.rd
            and self.ra == value.ra
            and self.z == value.z
            and self.ad == value.ad
            and self.cd == value.cd
            and self.rcode == value.rcode
            and self.qdcount == value.qdcount
            and self.ancount == value.ancount
            and self.nscount == value.nscount
            and self.arcount == value.arcount
        )


class DNSQuestion(DNSComponent):
    # https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
    def __init__(
        self, qname: str = "", qtype: QTYPE = QTYPE.A, qclass: QCLASS = QCLASS.IN
    ) -> None:
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass

    def toBytes(self) -> bytes:
        name = DNSComponent._nameToBytes(self.qname)
        return name + struct.pack(">HH", self.qtype.value, self.qclass.value)

    def fromBytes(full_data: bytes, count: int) -> tuple[list["DNSQuestion"], int]:
        questions = []
        offset = 12
        for _ in range(count):
            name, len = DNSComponent._readNameFromBytes(full_data, offset)
            offset += len
            qtype, qclass = struct.unpack(">HH", full_data[offset : offset + 4])
            offset += 4
            questions.append(DNSQuestion(name, QTYPE(qtype), QCLASS(qclass)))
        return questions, offset

    def __str__(self) -> str:
        return f"{self.qname:<37} {self.qclass:<12}{self.qtype}"

    def __repr__(self) -> str:
        return self.__str__()

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, DNSQuestion):
            return False
        return (
            self.qname == value.qname
            and self.qtype == value.qtype
            and self.qclass == value.qclass
        )


class SOARdata(DNSComponent):
    # https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.13
    def __init__(
        self,
        mname: str,
        rname: str,
        serial: int,
        refresh: int,
        retry: int,
        expire: int,
        minimum: int,
    ) -> None:
        self.mname = mname
        self.rname = rname
        self.serial = serial
        self.refresh = refresh
        self.retry = retry
        self.expire = expire
        self.minimum = minimum

    def toBytes(self) -> bytes:
        mname = DNSComponent._nameToBytes(self.mname)
        rname = DNSComponent._nameToBytes(self.rname)
        return (
            mname
            + rname
            + struct.pack(
                ">IIIII",
                self.serial,
                self.refresh,
                self.retry,
                self.expire,
                self.minimum,
            )
        )

    def fromBytes(full_data: bytes, offset: int) -> tuple["SOARdata", int]:
        mname, len = DNSComponent._readNameFromBytes(full_data, offset)
        offset += len
        rname, len = DNSComponent._readNameFromBytes(full_data, offset)
        offset += len
        serial, refresh, retry, expire, minimum = struct.unpack(
            ">IIIII", full_data[offset : offset + 20]
        )
        offset += 20
        return SOARdata(mname, rname, serial, refresh, retry, expire, minimum), offset

    def __str__(self) -> str:
        return f"{self.mname} {self.rname} {self.serial} {self.refresh} {self.retry} {self.expire} {self.minimum}"

    def __repr__(self) -> str:
        return self.__str__()

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, SOARdata):
            return False
        return (
            self.mname == value.mname
            and self.rname == value.rname
            and self.serial == value.serial
            and self.refresh == value.refresh
            and self.retry == value.retry
            and self.expire == value.expire
            and self.minimum == value.minimum
        )


class DNSRecord(DNSComponent):
    # https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3
    def __init__(
        self,
        name: str = "",
        qtype: QTYPE = QTYPE.A,
        ttl: int = 0,
        rdata: str = "",
        qclass: QCLASS = QCLASS.IN,
    ) -> None:
        self.name = name
        self.qtype = qtype
        self.qclass = qclass
        self.ttl = ttl
        self.rdata = rdata
        self.creation_time = datetime.datetime.now()

    def toBytes(self) -> bytes:
        name = DNSComponent._nameToBytes(self.name)
        if (
            self.qtype == QTYPE.NS
            or self.qtype == QTYPE.CNAME
            or self.qtype == QTYPE.PTR
        ):
            rdata = DNSComponent._nameToBytes(self.rdata)
        else:
            raise NotImplementedError
        return (
            name
            + struct.pack(
                ">HHIH", self.qtype.value, self.qclass.value, self.ttl, len(rdata)
            )
            + rdata
        )

    def fromBytes(
        full_data: bytes, count: int, offset: int
    ) -> tuple[list["DNSQuestion"], int]:
        records = []
        for _ in range(count):
            name, len = DNSComponent._readNameFromBytes(full_data, offset)
            offset += len
            qtype, qclass, ttl, rdlen = struct.unpack(
                ">HHIH", full_data[offset : offset + 10]
            )
            offset += 10
            if (
                qtype == QTYPE.NS.value
                or qtype == QTYPE.CNAME.value
                or qtype == QTYPE.PTR.value
            ):
                rdata, len = DNSComponent._readNameFromBytes(full_data, offset, rdlen)
            elif qtype == QTYPE.A.value:
                rdata = ""
                for i in range(4):
                    rdata += str(full_data[offset + i]) + "."
                rdata = rdata[:-1]
                len = rdlen
            elif qtype == QTYPE.AAAA.value:
                rdata = ""
                for i in range(0, rdlen, 2):
                    rdata += full_data[offset + i : offset + i + 2].hex() + ":"
                rdata = rdata[:-1]
                rdata = ipaddress.IPv6Address(rdata).compressed
                len = rdlen
            elif qtype == QTYPE.SOA.value:
                rdata, len = SOARdata.fromBytes(full_data, offset)
            offset += len
            records.append(DNSRecord(name, QTYPE(qtype), ttl, rdata, QCLASS(qclass)))
        return records, offset

    def __str__(self) -> str:
        return f"{self.name:<24} {self.ttl:<12} {self.qclass:<12} {self.qtype:<12} {self.rdata}"

    def __repr__(self) -> str:
        return self.__str__()

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, DNSRecord):
            return False
        return (
            self.name == value.name
            and self.qtype == value.qtype
            and self.qclass == value.qclass
            and self.ttl == value.ttl
            and self.rdata == value.rdata
        )


class DNSPacket(DNSComponent):
    def __init__(
        self,
        header: DNSHeader = DNSHeader(),
        questions: list[DNSQuestion] = [],
        answer_records: list[DNSRecord] = [],
        authority_records: list[DNSRecord] = [],
        additional_records: list[DNSRecord] = [],
    ) -> None:
        self.header = header
        self.question = questions or []
        header.qdcount = len(self.question)
        self.answer_records = answer_records or []
        header.ancount = len(self.answer_records)
        self.authority_records = authority_records or []
        header.nscount = len(self.authority_records)
        self.additional_records = additional_records or []
        header.arcount = len(self.additional_records)

    def toBytes(self) -> bytes:
        bytes_packet = self.header.toBytes()
        for question in self.question:
            bytes_packet += question.toBytes()
        for record in self.answer_records:
            bytes_packet += record.toBytes()
        for record in self.authority_records:
            bytes_packet += record.toBytes()
        for record in self.additional_records:
            bytes_packet += record.toBytes()
        return bytes_packet

    def fromBytes(data: bytes) -> "DNSPacket":
        header = DNSHeader.fromBytes(data)
        questions, offset = DNSQuestion.fromBytes(data, header.qdcount)
        answer_records, offset = DNSRecord.fromBytes(data, header.ancount, offset)
        authority_records, offset = DNSRecord.fromBytes(data, header.nscount, offset)
        additional_records, offset = DNSRecord.fromBytes(data, header.arcount, offset)
        return DNSPacket(
            header, questions, answer_records, authority_records, additional_records
        )

    def __str__(self) -> str:
        stringified = f"{self.header}\n"
        if self.question:
            stringified += "\nQuestions:\n"
            for question in self.question:
                stringified += f"{question}\n"
        if self.answer_records:
            stringified += "\nAnswer Records:\n"
            for record in self.answer_records:
                stringified += f"{record}\n"
        if self.authority_records:
            stringified += "\nAuthority Records:\n"
            for record in self.authority_records:
                stringified += f"{record}\n"
        return stringified

    def __repr__(self) -> str:
        return self.__str__()

    def __eq__(self, value: object) -> bool:
        if not isinstance(value, DNSPacket):
            return False
        return (
            self.header == value.header
            and self.question == value.question
            and self.answer_records == value.answer_records
            and self.authority_records == value.authority_records
            and self.additional_records == value.additional_records
        )
