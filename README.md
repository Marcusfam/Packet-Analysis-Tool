# Packet Analysis Tool

## Introduction

This project is part of the OS and Networks course assignment. The tool is designed to efficiently analyze network packets, detecting potential threats and intrusions by examining various packet attributes documented in the Request For Comments publications.

### Threading Model

The application utilizes a thread-pool model to manage the processing of incoming network packets. This design helps prevent the overhead associated with creating and destroying threads repeatedly.

### Packet Analysis

Packets are analyzed based on certain header attributes:
- **SYN Attacks:** Detection by inspecting the SYN flag within the TCP header.
- **ARP Responses:** Inspection of the Ethernet layer for ARP flag values.
- **HTTP Headers:** Analysis of URLs/domains against a list of blacklisted sites.

All packet data is converted from big endian to host endian (little endian) for consistent processing.

### Threading and Synchronization

Mutex locks are strategically used to prevent race conditions without degrading performance. The thread pool is initially sized to 12 threads, based on optimal performance observed during testing, particularly for systems with about 6 CPU cores.

## Testing

### Functionality Tests

The tool was tested under various conditions:
- High network traffic simulation using the `hping` command.
- Memory leak assessment with `Valgrind`.
- Detection of blacklisted URLs using the `wget` command on HTTP requests.

### Multi-threading Tests

The multithreading capabilities were verified by:
- Printing thread IDs within the analysis function.
- Measuring the time efficiency in packet processing with an increasing number of threads.

## Improvements

The current implementation has room for improvements:
- Threads are not properly joined at termination, which could be enhanced for cleaner shutdowns.
- Optimizing data structure access to reduce the need for mutex locks during intensive processing tasks.

## References

1. Multi-threads guide by Oracle. [Oracle Threading Guide](https://docs.oracle.com/cd/E26502_01/html/E35303/ggedh.html)
2. Queue data structure. [CS241 Labs](https://warwick.ac.uk/fac/sci/dcs/teaching/material/cs241/labs/)
3. Layers of packets. [RFC 791](https://www.rfc-editor.org/rfc/rfc791)


