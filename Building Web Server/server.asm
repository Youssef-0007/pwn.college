# Define constants
.equ AF_INET, 2       # IPv4
.equ SOCK_STREAM, 1   # TCP
.equ IPPROTO_IP, 0    # IP Protocol
.equ SYS_SOCKET, 41   # socket syscall
.equ SYS_BIND, 49     # bind syscall
.equ SYS_LISTEN, 50   # listen syscall
.equ SYS_ACCEPT, 43   # accept syscall
.equ SYS_READ, 0      # read syscall
.equ SYS_WRITE, 1     # write syscall
.equ SYS_OPEN, 2      # open syscall
.equ SYS_CLOSE, 3     # close syscall
.equ SYS_FORK, 57     # fork syscall
.equ SYS_EXIT, 60     # exit syscall
.equ SYS_WAIT, 61     # wait syscall
.equ SYS_SIGNAL, 13   # signal syscall
.equ SIGCHLD, 17      # SIGCHLD signal
.equ INADDR_ANY, 0    # Bind to any address (0.0.0.0)
.equ PORT, 80         # Port to bind to (HTTP port)
.equ BACKLOG, 5       # Backlog for listen
.equ BUFFER_SIZE, 4096 # Buffer size for reading client request
.equ O_RDONLY, 0      # Open file in read-only mode
.equ O_WRONLY, 1      # Open file in write-only mode
.equ O_CREAT, 64      # Create file if it does not exist
.equ O_TRUNC, 512     # Truncate file if it exists

.intel_syntax noprefix
.global _start

.section .data
http_response_200:
    .ascii "HTTP/1.0 200 OK\r\n\r\n"  # HTTP 200 response
http_response_200_len = . - http_response_200

.section .bss
.lcomm buffer, BUFFER_SIZE  # Buffer for reading client request
.lcomm file_buffer, BUFFER_SIZE  # Buffer for reading file contents

.section .text
_start:
    # Set up SIGCHLD handler
    mov rdi, SIGCHLD      # Signal: SIGCHLD
    lea rsi, sigchld_handler # Pointer to the signal handler
    mov rax, SYS_SIGNAL   # syscall: signal
    syscall

    # Create a socket using the socket syscall
    mov rdi, AF_INET      # domain: AF_INET (IPv4)
    mov rsi, SOCK_STREAM  # type: SOCK_STREAM (TCP)
    mov rdx, IPPROTO_IP   # protocol: IPPROTO_IP (IP)
    mov rax, SYS_SOCKET   # syscall: socket
    syscall

    # Check if socket creation was successful
    cmp rax, 0
    jl exit               # If rax < 0, exit (error)

    # Save the socket file descriptor
    mov rbx, rax          # rbx now holds the socket fd

    # Set up the sockaddr_in structure on the stack
    sub rsp, 16           # Allocate 16 bytes on the stack for sockaddr_in
    mov word ptr [rsp], AF_INET       # sin_family: AF_INET
    mov word ptr [rsp+2], 0x5000      # sin_port: 80 (in network byte order, 0x5000 = 80)
    mov dword ptr [rsp+4], INADDR_ANY # sin_addr: INADDR_ANY (0.0.0.0)
    mov qword ptr [rsp+8], 0          # Padding to make the structure 16 bytes

    # Bind the socket
    mov rdi, rbx          # socket fd
    lea rsi, [rsp]        # pointer to sockaddr_in structure
    mov rdx, 16           # length of sockaddr_in structure
    mov rax, SYS_BIND     # syscall: bind
    syscall

    # Check if bind was successful
    cmp rax, 0
    jl exit               # If rax < 0, exit (error)

    # Listen on the socket
    mov rdi, rbx          # socket fd
    mov rsi, BACKLOG      # backlog: 0 (as per challenge)
    mov rax, SYS_LISTEN   # syscall: listen
    syscall

    # Check if listen was successful
    cmp rax, 0
    jl exit               # If rax < 0, exit (error)

server_loop:
    # Accept an incoming connection
    mov rdi, rbx          # socket fd (listening socket)
    xor rsi, rsi          # NULL (no client address structure)
    xor rdx, rdx          # NULL (no client address length)
    mov rax, SYS_ACCEPT   # syscall: accept
    syscall

    # Check if accept was successful
    cmp rax, 0
    jl server_loop        # If rax < 0, continue accepting connections

    # Save the new socket file descriptor
    mov r12, rax          # r12 now holds the new socket fd

    # Fork a new process to handle the connection
    mov rax, SYS_FORK     # syscall: fork
    syscall

    # Check if fork was successful
    cmp rax, 0
    jl close_connection   # If rax < 0, close the connection

    # Child process
    cmp rax, 0
    je handle_connection  # If rax == 0, handle the connection

    # Parent process
    # Close the client socket in the parent process
    mov rdi, r12          # socket fd (new connection)
    mov rax, SYS_CLOSE    # syscall: close
    syscall

    # Repeat the server loop
    jmp server_loop

handle_connection:
    # Close the listening socket in the child process
    mov rdi, rbx          # listening socket fd
    mov rax, SYS_CLOSE    # syscall: close
    syscall

    # Read the client's request
    mov rdi, r12          # socket fd (new connection)
    lea rsi, [buffer]     # pointer to the buffer
    mov rdx, BUFFER_SIZE  # buffer size
    mov rax, SYS_READ     # syscall: read
    syscall

    # Check if read was successful
    cmp rax, 0
    jl close_connection   # If rax < 0, close the connection

    # Determine if the request is GET or POST
    lea rdi, [buffer]     # Pointer to the buffer
    call get_request_type # Call the get_request_type function
    cmp rax, 0
    je handle_get         # If GET, handle GET request
    cmp rax, 1
    je handle_post        # If POST, handle POST request

    # If neither, close the connection
    jmp close_connection

handle_get:
    # Parse the URL path
    lea rdi, [buffer]     # Pointer to the buffer
    call parse_get_url_path   # Call the parse_get_url_path function
    mov r13, rax          # Save the URL path in r13

    # Open the requested file
    mov rdi, r13          # URL path
    mov rsi, O_RDONLY     # Open in read-only mode
    mov rax, SYS_OPEN     # syscall: open
    syscall

    # Check if open was successful
    cmp rax, 0
    jl close_connection   # If rax < 0, close the connection

    # Save the file descriptor
    mov r14, rax          # r14 now holds the file fd

    # Read the file contents
    mov rdi, r14          # file fd
    lea rsi, [file_buffer] # pointer to the file buffer
    mov rdx, BUFFER_SIZE  # buffer size
    mov rax, SYS_READ     # syscall: read
    syscall

    # Check if read was successful
    cmp rax, 0
    jl close_file         # If rax < 0, close the file

    # Save the number of bytes read
    mov r15, rax          # r15 now holds the number of bytes read

    # Close the file
    mov rdi, r14          # file fd
    mov rax, SYS_CLOSE    # syscall: close
    syscall

    # Send the HTTP 200 response
    mov rdi, r12          # socket fd (new connection)
    lea rsi, [http_response_200]  # pointer to the HTTP 200 response
    mov rdx, http_response_200_len # length of the HTTP 200 response
    mov rax, SYS_WRITE    # syscall: write
    syscall

    # Check if write was successful
    cmp rax, http_response_200_len
    jne close_connection  # If not all bytes were written, close the connection

    # Send the file contents to the client
    mov rdi, r12          # socket fd (new connection)
    lea rsi, [file_buffer] # pointer to the file buffer
    mov rdx, r15          # number of bytes read (saved in r15)
    mov rax, SYS_WRITE    # syscall: write
    syscall

    # Check if write was successful
    cmp rax, rdx
    jne close_connection  # If not all bytes were written, close the connection

    jmp close_connection

handle_post:
    # Parse the URL path
    lea rdi, [buffer]     # Pointer to the buffer
    call parse_post_url_path   # Call the parse_post_url_path function
    mov r13, rax          # Save the URL path in r13

    # Parse the Content-Length header
    lea rdi, [buffer]     # Pointer to the buffer
    call parse_content_length  # Call the parse_content_length function
    mov r14, rax          # Save the Content-Length in r14

    # Find the start of the POST data (after \r\n\r\n)
    lea rdi, [buffer]     # Pointer to the buffer
    call find_post_data   # Call the find_post_data function
    mov r15, rax          # Save the start of the POST data in r15

    # Open the file for writing
    mov rdi, r13          # URL path
    mov rsi, O_WRONLY | O_CREAT  # Open flags
    mov rdx, 0644         # File permissions (rw-r--r--)
    mov rax, SYS_OPEN     # syscall: open
    syscall

    # Check if open was successful
    cmp rax, 0
    jl close_connection   # If rax < 0, close the connection

    # Save the file descriptor
    mov r13, rax          # r13 now holds the file fd

    # Write the POST data to the file
    mov rdi, r13          # file fd
    mov rsi, r15          # Pointer to the POST data
    mov rdx, r14          # Content-Length
    mov rax, SYS_WRITE    # syscall: write
    syscall

    # Check if write was successful
    cmp rax, r14
    jne close_file        # If not all bytes were written, close the file

    # Close the file
    mov rdi, r13          # file fd
    mov rax, SYS_CLOSE    # syscall: close
    syscall

    # Send the HTTP 200 response
    mov rdi, r12          # socket fd (new connection)
    lea rsi, [http_response_200]  # pointer to the HTTP 200 response
    mov rdx, http_response_200_len # length of the HTTP 200 response
    mov rax, SYS_WRITE    # syscall: write
    syscall

    # Check if write was successful
    cmp rax, http_response_200_len
    jne close_connection  # If not all bytes were written, close the connection

close_connection:
    # Close the new socket
    mov rdi, r12          # socket fd (new connection)
    mov rax, SYS_CLOSE    # syscall: close
    syscall

    # Exit the child process
    mov rdi, 0            # exit code: 0
    mov rax, SYS_EXIT     # syscall: exit
    syscall

close_file:
    # Close the file
    mov rdi, r13          # file fd
    mov rax, SYS_CLOSE    # syscall: close
    syscall

    jmp close_connection

exit:
    # Clean up the stack
    add rsp, 16           # Deallocate the 16 bytes

    # Exit the program
    mov rdi, 0            # exit code: 0
    mov rax, SYS_EXIT     # syscall: exit
    syscall

# Function to handle SIGCHLD signals
sigchld_handler:
    # Clean up zombie child processes
    mov rdi, -1           # Wait for any child process
    xor rsi, rsi          # No status
    mov rdx, 0            # No options
    mov rax, SYS_WAIT     # syscall: wait
    syscall
    ret

# Function to determine the request type (GET or POST)
get_request_type:
    # rdi: Pointer to the buffer containing the HTTP request
    # Returns: 0 for GET, 1 for POST, -1 for unknown in rax

    # Check if the request starts with "GET "
    mov al, byte ptr [rdi]    # Load the first character
    cmp al, 'G'
    jne check_post            # If not 'G', check for POST
    mov al, byte ptr [rdi+1]  # Load the second character
    cmp al, 'E'
    jne unknown               # If not 'E', unknown request
    mov al, byte ptr [rdi+2]  # Load the third character
    cmp al, 'T'
    jne unknown               # If not 'T', unknown request
    mov al, byte ptr [rdi+3]  # Load the fourth character
    cmp al, ' '
    jne unknown               # If not ' ', unknown request
    mov rax, 0                # Return 0 (GET request)
    ret

check_post:
    # Check if the request starts with "POST"
    mov al, byte ptr [rdi]    # Load the first character
    cmp al, 'P'
    jne unknown               # If not 'P', unknown request
    mov al, byte ptr [rdi+1]  # Load the second character
    cmp al, 'O'
    jne unknown               # If not 'O', unknown request
    mov al, byte ptr [rdi+2]  # Load the third character
    cmp al, 'S'
    jne unknown               # If not 'S', unknown request
    mov al, byte ptr [rdi+3]  # Load the fourth character
    cmp al, 'T'
    jne unknown               # If not 'T', unknown request
    mov rax, 1                # Return 1 (POST request)
    ret

unknown:
    mov rax, -1               # Return -1 (unknown request)
    ret

# Function to parse the URL path from the HTTP request
parse_get_url_path:
    # rdi: Pointer to the buffer containing the HTTP request
    # Returns: Pointer to the URL path in rax

    # Look for the first space after "GET "
    lea rsi, [rdi + 4]    # Skip "GET "
find_space_g:
    cmp byte ptr [rsi], ' '
    je found_space_g
    inc rsi
    jmp find_space_g

found_space_g:
    # Replace the space with a null terminator
    mov byte ptr [rsi], 0

    # Return the pointer to the URL path
    lea rax, [rdi + 4]
    ret

# Function to parse the URL path from the HTTP request
parse_post_url_path:
 # rdi: Pointer to the buffer containing the HTTP request
    # Returns: Pointer to the URL path in rax

    # Look for the first space after "POST "
    lea rsi, [rdi + 5]    # Skip "POST "
find_space_p:
    cmp byte ptr [rsi], ' '
    je found_space_p
    inc rsi
    jmp find_space_p
    
found_space_p:
    # Replace the space with a null terminator
    mov byte ptr [rsi], 0

    # Return the pointer to the URL path
    lea rax, [rdi + 5]
    ret

# Function to parse the Content-Length header
parse_content_length:
    # rdi: Pointer to the buffer containing the HTTP request
    # Returns: Content-Length in rax

    # Look for the "Content-Length: " header
    lea rsi, [rdi]        # Start of the buffer
find_content_length:
    # Compare "Content-Length: " character by character
    cmp byte ptr [rsi], 'C'
    jne next_char
    cmp byte ptr [rsi+1], 'o'
    jne next_char
    cmp byte ptr [rsi+2], 'n'
    jne next_char
    cmp byte ptr [rsi+3], 't'
    jne next_char
    cmp byte ptr [rsi+4], 'e'
    jne next_char
    cmp byte ptr [rsi+5], 'n'
    jne next_char
    cmp byte ptr [rsi+6], 't'
    jne next_char
    cmp byte ptr [rsi+7], '-'
    jne next_char
    cmp byte ptr [rsi+8], 'L'
    jne next_char
    cmp byte ptr [rsi+9], 'e'
    jne next_char
    cmp byte ptr [rsi+10], 'n'
    jne next_char
    cmp byte ptr [rsi+11], 'g'
    jne next_char
    cmp byte ptr [rsi+12], 't'
    jne next_char
    cmp byte ptr [rsi+13], 'h'
    jne next_char
    cmp byte ptr [rsi+14], ':'
    jne next_char
    cmp byte ptr [rsi+15], ' '
    jne next_char

    # If we reach here, we've found the "Content-Length: " header
    add rsi, 16           # Skip "Content-Length: "
    jmp parse_length

next_char:
    inc rsi               # Move to the next character
    jmp find_content_length

parse_length:
    # Convert the ASCII length to an integer
    xor rax, rax          # Clear rax
convert_loop:
    movzx rcx, byte ptr [rsi]  # Load the next byte
    cmp rcx, '\r'         # Check for end of line
    je done
    sub rcx, '0'          # Convert ASCII to integer
    imul rax, 10          # Multiply current value by 10
    add rax, rcx          # Add the new digit
    inc rsi               # Move to the next character
    jmp convert_loop

done:
    ret

# Function to find the start of the POST data
find_post_data:
    # rdi: Pointer to the buffer containing the HTTP request
    # Returns: Pointer to the start of the POST data in rax

    # Look for the \r\n\r\n sequence
    lea rsi, [rdi]        # Start of the buffer
find_crlf:
    cmp byte ptr [rsi], '\r'
    jne next_byte
    cmp byte ptr [rsi+1], '\n'
    jne next_byte
    cmp byte ptr [rsi+2], '\r'
    jne next_byte
    cmp byte ptr [rsi+3], '\n'
    jne next_byte
    add rsi, 4            # Skip \r\n\r\n
    mov rax, rsi          # Return the start of the POST data
    ret

next_byte:
    inc rsi               # Move to the next character
    jmp find_crlf
