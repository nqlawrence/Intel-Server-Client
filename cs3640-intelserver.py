import socket
import ssl
import dns.resolver
from ipwhois import IPWhois

# Define the server address and port
HOST = '127.0.0.1'
PORT = 5555

# Create a socket and start listening for incoming connections
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(5)

# Initialize a DNS resolver using CloudFlare's public DNS server
resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = ['1.1.1.1', '1.0.0.1']

#Client Command for IPV4_ADDR
def resolve_ipv4_address(domain):
    try:
        answers = resolver.resolve(domain, rdtype='A')
        ipv4_address = answers[0].address
        return ipv4_address
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return "Domain not found or no IPv4 address available"
    except Exception as e:
        return str(e)

#Client Command for IPV6_ADDR
def resolve_ipv6_address(domain):
    try:
        answers = resolver.resolve(domain, rdtype='AAAA')
        ipv6_address = answers[0].address
        return ipv6_address
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return "Domain not found or no IPv6 address available"
    except Exception as e:
        return str(e)

#Client Command for TLS_CERT
def get_tls_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as sslsock:
                cert = sslsock.getpeercert()
                return cert
    except Exception as e:
        return str(e)

#Client Command for HOSTING_AS
def get_as_info(domain):
    try:
        ip_address = resolve_ipv4_address(domain)

        obj = IPWhois(ip_address)
        result = obj.lookup_rdap()

        # Extract AS information
        asn = result.get('asn', 'N/A')
        description = result.get('asn_description', 'N/A')

        return f"AS: {asn}, AS Name: {description}"
    except Exception as e:
        return f"Error retrieving AS information: {str(e)}"

#Client Command for Organization
def get_organization_name(domain):
    try:
        cert = get_tls_certificate(domain)

        # Extracts the subject field
        subject_field = cert.get('subject', ())

        # Check if the subject field is a tuple
        if isinstance(subject_field, tuple) and len(subject_field) > 0:
            # Iterate through the tuples to find a relevant attribute, each domain has a different tuple in where it stores the organization name.
            for field in subject_field:
                for attribute in field:
                    # Check for attributes that might contain organization information
                    relevant_attributes = ['organizationName', 'organization', 'O']
                    if attribute[0] in relevant_attributes:
                        org_name = attribute[1]
                        return org_name.decode('utf-8') if isinstance(org_name, bytes) else org_name

        # If not a tuple or relevant attribute not found, assume it's bytes and convert to string
        return subject_field.decode('utf-8') if isinstance(subject_field, bytes) else str(subject_field)
    except Exception as e:
        return f"Error extracting organization name: {str(e)}"




# Define the main server loop
def run_server():

    print(f"Listening on {HOST}:{PORT}")

    while True:
        client_socket, addr = server.accept()
        print(f"Accepted connection from {addr[0]}:{addr[1]}")

        # Receive the client request
        request = client_socket.recv(1024).decode('utf-8')

        # Split the client request into command and parameter
        command, parameter = request.split(":")

        # Process the client request and send the response
        if command == "IPV4_ADDR":
            response = resolve_ipv4_address(parameter)
        elif command == "IPV6_ADDR":
            response = resolve_ipv6_address(parameter)
        elif command == "TLS_CERT":
            response = str(get_tls_certificate(parameter))
        elif command == "HOSTING_AS":
            response = get_as_info(parameter)
        elif command == "ORGANIZATION":
            response = get_organization_name(parameter)
        else:
            response = "Invalid command"

        # Send the response back to the client
        client_socket.send(response.encode('utf-8'))

        # Close the client socket
        client_socket.close()

if __name__ == "__main__":
    run_server()
