## Overview

Socket programming is a way of enabling communication between two processes over a network. In client-server architecture, one process (the server) listens for incoming connections while the other process (the client) initiates the connection.

TCP (Transmission Control Protocol) and UDP (User Datagram Protocol) are two protocols used for socket communication. TCP is a connection-oriented protocol, meaning that it establishes a connection between the two parties and ensures the reliable delivery of data packets. UDP, on the other hand, is a connectionless protocol that does not establish a connection and does not guarantee reliable delivery of data packets.

## TCP Socket Programming

In TCP socket programming, the server listens for incoming connections on a specific port. Once a client initiates a connection to the server, the server accepts the connection and creates a new socket for the communication with that client. The client also creates a socket and connects to the server's socket.

The steps involved in TCP socket programming are:

    The server creates a socket using the socket() system call and binds it to a specific IP address and port using the bind() system call.

    The server then listens for incoming connections using the listen() system call.

    When a client initiates a connection to the server, the server accepts the connection using the accept() system call. This creates a new socket for communication with that client.

    The client creates a socket using the socket() system call and connects to the server's socket using the connect() system call.

    Once the connection is established, both the server and client can send and receive data using the send() and recv() system calls.

    Finally, when the communication is complete, both the server and client close their sockets using the close() system call.

## UDP Socket Programming

In UDP socket programming, there is no connection establishment between the two parties. Instead, both the client and server can send and receive packets of data at any time.

The steps involved in UDP socket programming are:

    Both the server and client create sockets using the socket() system call.

    The server binds the socket to a specific IP address and port using the bind() system call.

    Both the server and client can send packets of data using the sendto() system call, which specifies the destination IP address and port.

    Both the server and client can receive packets of data using the recvfrom() system call, which retrieves the source IP address and port of the packet.

    Finally, when the communication is complete, both the server and client close their sockets using the close() system call.

### Conclusion

In summary, socket client-server TCP/UDP communication involves establishing a connection between two processes over a network using either the TCP or UDP protocol. TCP is a connection-oriented protocol that ensures reliable delivery of data packets, while UDP is a connectionless protocol that does not establish a connection and does not guarantee reliable delivery of data packets. The process of socket programming involves creating sockets, establishing connections, sending and receiving data packets, and closing sockets once the communication is complete.