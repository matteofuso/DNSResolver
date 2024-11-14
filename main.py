import DNSResolver

def main():
    resolver = DNSResolver.DNSResolver()
    
    while True:
        print("\nDNS Query Menu")
        print("1. Perform DNS query (A record)")
        print("2. Perform Reverse DNS query (IPv4)")
        print("3. Perform Reverse DNS query (IPv6)")
        print("4. Exit")
        
        choice = input("Enter your choice (1-4): ")
        
        if choice == '1':
            fqdn = input("Enter the domain name for DNS query: ")
            print("\nDNS response for", fqdn)
            a_response = resolver.recursive_query(fqdn, DNSResolver.DNSPacket.QTYPE.A)
            print("Parsed DNS response:", a_response)
        
        elif choice == '2':
            ipv4 = input("Enter the IPv4 address for Reverse DNS lookup: ")
            print("\nReverse DNS IPv4 response for", ipv4)
            reverse_v4 = resolver.reverse_lookup_v4(ipv4)
            print("Parsed Reverse DNS IPv4 response:", reverse_v4)
        
        elif choice == '3':
            ipv6 = input("Enter the IPv6 address for Reverse DNS lookup: ")
            print("\nReverse DNS IPv6 response for", ipv6)
            reverse_v6 = resolver.reverse_lookup_v6(ipv6)
            print("Parsed Reverse DNS IPv6 response:", reverse_v6)
        
        elif choice == '4':
            print("Exiting program...")
            break
        
        else:
            print("Invalid choice, please enter a number between 1 and 4.")

if __name__ == "__main__":
    main()
