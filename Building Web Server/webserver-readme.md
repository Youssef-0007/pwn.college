# Assembly Web Server

## Project Overview
This repository contains a basic HTTP web server implemented in x86-64 assembly language for Linux systems. The project was developed as part of the pwn.college "Playing with Programs" section in the "Web Talking" module. This implementation demonstrates low-level network programming concepts by creating a functional web server capable of handling both GET and POST requests entirely in assembly language.

## Features
- Socket creation and TCP/IP networking
- Concurrent connection handling with process forking
- HTTP protocol implementation (basic)
- Support for both GET and POST requests
- File I/O operations for serving and storing content
- Signal handling for child process management

## Technical Details

### Network Implementation
The server:
- Creates a socket using the socket syscall
- Binds to port 80 (HTTP standard port)
- Listens for incoming connections
- Accepts connections and forks new processes to handle requests
- Implements proper cleanup of child processes with SIGCHLD handling

### HTTP Protocol Support
The server processes:
- GET requests: Reads and serves requested files
- POST requests: Parses request body and writes data to files
- HTTP header parsing (Content-Length extraction)
- Basic HTTP response formatting

### System Calls Used
The implementation leverages various Linux syscalls:
- Network: socket, bind, listen, accept
- Process: fork, wait, exit
- File: open, read, write, close
- Signal: signal

## Skills Gained

### Assembly Language Mastery
- Register usage and management in complex programs
- Stack manipulation for local variables
- Function calling conventions
- Byte-level string processing

### Low-Level Networking
- Socket programming at the syscall level
- Network byte order considerations
- TCP connection handling

### System Programming
- Process management with fork()
- Signal handling
- File descriptor management
- Understanding the Linux syscall interface

### Protocol Implementation
- HTTP request parsing
- Content-Length header processing
- Implementation of different HTTP methods (GET/POST)
- Response formatting

### Memory Management
- Buffer allocation and usage
- String parsing without higher-level abstractions
- Memory safety considerations

## Usage
1. Assemble the code:
   ```
   as -o webserver.o webserver.s
   ```

2. Link the object file:
   ```
   ld -o webserver webserver.o
   ```

3. Run the server (requires root privileges for port 80):
   ```
   sudo ./webserver
   ```

4. Access the server through a web browser at http://localhost or using curl:
   ```
   curl http://localhost/path/to/file
   ```

## Security Considerations
This implementation is primarily educational and lacks several security features found in production web servers:
- No input validation or sanitization
- Limited error handling
- No protection against buffer overflows
- No TLS/SSL support

## Learning Outcomes
This project demonstrates the ability to work with complex systems programming concepts directly at the assembly level, bypassing higher-level abstractions typically provided by programming languages. It showcases a deep understanding of how networking, process management, and file operations work at the operating system interface level.
