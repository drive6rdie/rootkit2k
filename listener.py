import socket

def handle_command(command):
    if command == "help":
        res = "Available commands :\nhelp\nshadow\nexit"
        return res
    elif command == "shadow":
        try:
            # Envoyer la commande au module kernel
            with open("/proc/shadow_cmd", "w") as proc_file:
                proc_file.write(command)

            # Lire la réponse du module
            with open("/proc/shadow_cmd", "r") as proc_file:
                return proc_file.read()
        except Exception as e:
            return f"Error: {e}"
    else:
        return "Unknown command"

def start_server(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen(1)
        print(f"Server listening on {host}:{port}...")
        
        while True:
            client_socket, client_address = server_socket.accept()
            with client_socket:
                print(f"Connection from {client_address}")
                data = client_socket.recv(2048).decode()
                if not data:
                    continue
                
                print(f"Received: {data}")
                response = handle_command(data.strip())
                
                client_socket.sendall(response.encode())

if __name__ == "__main__":
    server_host = "127.0.0.1"
    server_port = 4444
    start_server(server_host, server_port)
