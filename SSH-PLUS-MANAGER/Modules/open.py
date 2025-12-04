#!/usr/bin/env python3
# encoding: utf-8
# SSHPLUS By @Crazy_vpn
# Refactored to asyncio by Gemini
import asyncio
import sys
import argparse
from os import system

# --- Configuration ---
# End of line characters
CRLF = b'\r\n'

# Default values
DEFAULT_IP = '0.0.0.0'
DEFAULT_PORT = 8080
DEFAULT_HOST = '0.0.0.0:1194'  # Default for OpenVPN
DEFAULT_PASS = ''

# Buffer size
BUFLEN = 8192 * 2

# Connection timeout
TIMEOUT = 60

# --- HTTP Response ---
MSG = b'SSHPLUS'
RESPONSE = b"HTTP/1.1 200 " + MSG + CRLF * 2

def find_header(headers, key, default=''):
    """
    Finds a header in a list of (key, value) tuples.
    """
    for k, v in headers:
        if k.lower() == key.lower():
            return v
    return default

async def pipe_stream(reader, writer, name=""):
    """
    Reads data from a reader and writes it to a writer.
    """
    try:
        while not reader.at_eof():
            data = await reader.read(BUFLEN)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        pass  # Connection closed
    finally:
        if not writer.is_closing():
            writer.close()
            await writer.wait_closed()

async def handle_connection(client_reader, client_writer):
    """
    Handles a new client connection.
    """
    addr = client_writer.get_extra_info('peername')
    print(f"New connection from {addr}")

    target_reader, target_writer = None, None

    try:
        # Read the request line and headers from the client
        request_line_bytes = await asyncio.wait_for(client_reader.readuntil(CRLF), timeout=TIMEOUT)
        
        # Read headers until a blank line is found
        header_bytes = await asyncio.wait_for(client_reader.readuntil(CRLF * 2), timeout=TIMEOUT)
        
        # Decode for parsing
        full_request = (request_line_bytes + header_bytes).decode('iso-8859-1')
        
        # Simple header parsing
        headers = [
            line.split(":", 1)
            for line in full_request.split('\r\n')
            if ":" in line
        ]
        headers = [(k.strip(), v.strip()) for k, v in headers]

        # Get target host and port from X-Real-Host or use default
        host_port = find_header(headers, 'X-Real-Host', DEFAULT_HOST)
        
        # Handle X-Split header (consume extra data if present)
        if find_header(headers, 'X-Split'):
            await asyncio.wait_for(client_reader.read(BUFLEN), timeout=TIMEOUT)
            
        # Password protection
        if DEFAULT_PASS:
            passwd = find_header(headers, 'X-Pass')
            if passwd != DEFAULT_PASS:
                print(f"Forbidden: Incorrect password from {addr}")
                client_writer.write(b'HTTP/1.1 400 WrongPass!\r\n\r\n')
                await client_writer.drain()
                return

        # Split host and port
        host, port_str = (host_port.split(":") + [None])[:2]
        port = int(port_str) if port_str is not None else 1194 # Default to OpenVPN port

        # Connect to the target
        print(f"Connecting to {host}:{port} for {addr}")
        target_reader, target_writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=TIMEOUT
        )

        # Send the successful connection response to the client
        client_writer.write(RESPONSE)
        await client_writer.drain()

        # Start piping data in both directions
        task_client_to_target = asyncio.create_task(
            pipe_stream(client_reader, target_writer, "c->t")
        )
        task_target_to_client = asyncio.create_task(
            pipe_stream(target_reader, client_writer, "t->c")
        )

        await asyncio.gather(task_client_to_target, task_target_to_client)

    except asyncio.TimeoutError:
        print(f"Timeout with connection {addr}")
    except Exception as e:
        print(f"Error with connection {addr}: {e}")
    finally:
        print(f"Closing connection from {addr}")
        if not client_writer.is_closing():
            client_writer.close()
            await client_writer.wait_closed()
        if target_writer and not target_writer.is_closing():
            target_writer.close()
            await target_writer.wait_closed()

async def main():
    """
    Main function to start the server.
    """
    system("clear")
    parser = argparse.ArgumentParser(description="Asyncio HTTP Proxy for OpenVPN")
    parser.add_argument('port', nargs='?', type=int, default=DEFAULT_PORT,
                        help=f"Port to listen on (default: {DEFAULT_PORT})")
    
    args = parser.parse_args()
    
    port = args.port

    print("\033[0;34m━"*8, "\033[1;32m PROXY SOCKS (Async)", "\033[0;34m━"*8, "\n")
    print(f"\033[1;33mIP:\033[1;32m {DEFAULT_IP}")
    print(f"\033[1;33mPORT:\033[1;32m {port}\n")
    print("\033[0;34m━"*10, "\033[1;32m SSHPLUS", "\033[0;34m━\033[1;37m"*11, "\n")

    server = await asyncio.start_server(handle_connection, DEFAULT_IP, port)

    addr = server.sockets[0].getsockname()
    print(f'Server listening on {addr}')

    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print('\nStopping server...')