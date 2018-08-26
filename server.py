import asyncio
import re
import logging
from hashlib import sha1
from base64 import b64encode

async def handshake(reader, writer):
    data = await reader.readuntil(b'\r\n\r\n')
    message = data.decode()
    regex = re.search('Sec-WebSocket-Key: (.+)\r\n', message, re.IGNORECASE)
    key = regex.group(1)
    temp = (key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()
    accept_key = b64encode(sha1(temp).digest()).decode()
    header = 'HTTP/1.1 101 Switching Protocols\r\n'
    header += 'Upgrade: websocket\r\n'
    header += 'Connection: Upgrade\r\n'
    header += 'Sec-WebSocket-Accept: ' + accept_key + '\r\n\r\n'
    encoded_header = header.encode()
    writer.write(encoded_header)
    await writer.drain()

async def get_data(reader):
    # Diagram given by the document detailing Websockets, RFC6455:
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-------+-+-------------+-------------------------------+
    # |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
    # |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
    # |N|V|V|V|       |S|             |   (if payload len==126/127)   |
    # | |1|2|3|       |K|             |                               |
    # +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
    # |     Extended payload length continued, if payload len == 127  |
    # + - - - - - - - - - - - - - - - +-------------------------------+
    # |                               |Masking-key, if MASK set to 1  |
    # +-------------------------------+-------------------------------+
    # | Masking-key (continued)       |          Payload Data         |
    # +-------------------------------- - - - - - - - - - - - - - - - +
    # :                     Payload Data continued ...                :
    # + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
    # |                     Payload Data continued ...                |
    # +---------------------------------------------------------------+
    data = await reader.readexactly(2)
    # Generate a list of ints representing half-bytes
    intlist = [int(x, 16) for x in data.hex()]
    #print("Data:", ' '.join([hex(x) for x in data]))
    if intlist[0] == 8:
        fin = True
    elif intlist[0] == 0:
        fin = False
    else:
        print("Error: RSV1 or RSV2 or RSV3 not set to 0.")
        raise ValueError
    if intlist[1] != 0 and intlist[1] != 1 and intlist[1] != 8:
        print("Error: don't know the opcode '" + str(intlist[1]) + "'.")
        raise ValueError
    elif intlist[1] == 8:
        print("Client asking to close the connection.")
        return None
    if intlist[2] >= 8:
        masked = True
        intlist[2] -= 8
    else:
        masked = False
    payload_length = 16 * intlist[2] + intlist[3]
    if payload_length == 126:
        data = await reader.readexactly(2)
        payload_length = int.from_bytes(data, byteorder='big')
    elif payload_length == 127:
        data = await reader.readexactly(8)
        payload_length = int.from_bytes(data, byteorder='big')
    if masked:
        mask = await reader.readexactly(4)
    data = await reader.readexactly(payload_length)
    if masked:
        # Octet i of the transformed data is the XOR of
        # octet i of the original data with octet at index
        # i modulo 4 of the masking key
        unmasked_data = [data[i] ^ mask[i % 4] for i in range(len(data))]
        payload = bytearray(unmasked_data).decode()
    else:
        payload = data.decode()
    return payload

async def send_data(writer, data):
    frame = [129]
    if 125 < len(data) < 65536:
        frame.append(126)
        frame.extend(len(data).to_bytes(2, byteorder='big'))
    elif len(data) >= 65536:
        frame.append(127)
        frame.extend(len(data).to_bytes(8, byteorder='big'))
    else:
        frame.append(len(data))
    writer.write(bytearray(frame) + data.encode())
    await writer.drain()

async def run_connection(reader, writer):
    addr = writer.get_extra_info('peername')
    await handshake(reader, writer)
    print("Connection established with", addr[1], "from", addr[0])

    from_client = await get_data(reader)
    if from_client == None:
        print("Closing the client socket")
        writer.close()
        return
    print("From client:", from_client)
    print("Sending the same data")
    await send_data(writer, from_client)

loop = asyncio.get_event_loop()
coro = asyncio.start_server(run_connection, '127.0.0.1', 8888, loop=loop)
server = loop.run_until_complete(coro)

# Serve requests until Ctrl+C is pressed
socket_name = server.sockets[0].getsockname()
print("Serving on port", socket_name[1], "at", socket_name[0])
try:
    loop.run_forever()
except KeyboardInterrupt:
    print("Closing server")

# Close the server
server.close()
loop.run_until_complete(server.wait_closed())
loop.close()
