from DNSResolver import DNSResolver


def main():
    resolver = DNSResolver.DNSResolver()
    while True:
        print("\nDNS Query Menu")
        print("1. Perform Domain Lookup")
        print("2. Perform Reverse DNS query (IPv4)")
        print("3. Perform Reverse DNS query (IPv6)")
        print("4. Custom Query")
        print("5. Exit")
        choice = input("Enter your choice (1-4): ")
        if choice == "1":
            fqdn = input("Enter the domain name for DNS query: ")
            print("\nDNS response for", fqdn)
            response = resolver.recursive_query(fqdn, DNSResolver.DNSPacket.QTYPE.A)
        elif choice == "2":
            ipv4 = input("Enter the IPv4 address for Reverse DNS lookup: ")
            print("\nReverse DNS IPv4 response for", ipv4)
            response = resolver.reverse_lookup_v4(ipv4)
        elif choice == "3":
            ipv6 = input("Enter the IPv6 address for Reverse DNS lookup: ")
            print("\nReverse DNS IPv6 response for", ipv6)
            response = resolver.reverse_lookup_v6(ipv6)
        elif choice == "4":
            fqdn = input("Enter the domain name for DNS query: ")
            qtype = input("Enter the query type (A, AAAA, MX, TXT, etc.): ")
            print("\nDNS response for", fqdn)
            response = resolver.recursive_query(fqdn, qtype)
        elif choice == "5":
            print("Exiting program...")
            break
        else:
            print("Invalid choice, please enter a number between 1 and 4.")
        if response:
            print(response)
        else:
            print("No response received.")


if __name__ == "__main__":
    main()
