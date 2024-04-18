import socket
import argparse

def send_request(server_addr, server_port, domain, service):
    try:
        # Create a socket and connect to the Intel Server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_addr, server_port))

        # Construct the client command
        client_command = f"{service}:{domain}"

        # Send the client command to the server
        client_socket.send(client_command.encode('utf-8'))

        # Receive and print the server response
        response = client_socket.recv(1024).decode('utf-8')
        print(f"Server Response: {response}")

        # Close the socket
        client_socket.close()

    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    # Set up argparse for command-line argument parsing
    parser = argparse.ArgumentParser(description="Intel Client")
    parser.add_argument("intel_server_addr", help="The address of the Intel Server")
    parser.add_argument("intel_server_port", type=int, help="The port of the Intel Server")
    parser.add_argument("domain", help="The domain for the query")
    parser.add_argument("service", choices=["IPV4_ADDR", "IPV6_ADDR", "TLS_CERT", "HOSTING_AS", "ORGANIZATION"],
                        help="The service to be performed")

    # Parse command line arguments
    args = parser.parse_args()

    # Send the request to the Intel Server
    send_request(args.intel_server_addr, args.intel_server_port, args.domain, args.service)
