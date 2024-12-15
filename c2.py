import socket

def send_command_to_server(host, port, command):
    try:
        # Créer un socket client
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((host, port))
            client_socket.sendall(command.encode())
            response = client_socket.recv(1024).decode()
            return response
    except Exception as e:
        return f"Error: {e}"

if __name__ == "__main__":
    server_host = "127.0.0.1"
    server_port = 4444  
    
    print("Type a command to send to the server (type 'exit' to quit).")
    while True:
        user_input = input("> ")
        if user_input.lower() == "exit":
            print("Goodbye!")
            break
        
        response = send_command_to_server(server_host, server_port, user_input)
        print(f"Server response:\n {response}")
