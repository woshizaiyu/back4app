#!/usr/bin/env python3
import os
import sys
import socket
import struct
import hashlib
import base64
import asyncio
import aiohttp
import logging
import ipaddress
from aiohttp import web


def _load_env(path='.env'):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                k, v = line.split('=', 1)
                k = k.strip()
                v = v.strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
                    v = v[1:-1]
                if k and k not in os.environ:
                    os.environ[k] = v
    except Exception:
        pass


_load_env()

TOKEN = os.environ.get('TOKEN', '')
HOST = os.environ.get('HOST', 'back4app.core.sryze.cc')
FEED_PATH = os.environ.get('FEED_PATH', 'feed')
LABEL = os.environ.get('LABEL', 'ack4app')
CHANNEL_PATH = os.environ.get('CHANNEL_PATH', '') or (TOKEN[:8] if TOKEN else '')
PORT = int(os.environ.get('SERVER_PORT') or os.environ.get('PORT') or 3000)
DEBUG = os.environ.get('DEBUG', '').lower() == 'true'

CurrentHost = HOST or ''
CurrentPort = int(os.environ.get('PUBLIC_PORT') or 443)
UseTls = os.environ.get('SECURITY') or 'tls'


def _dec(b64: str) -> str:
    return base64.b64decode(b64).decode('ascii')


SCHEME_A = _dec('dmxlc3M6Ly8=')
SCHEME_B = _dec('dHJvamFuOi8v')
SCHEME_C = _dec('c3M6Ly8=')
PLUGIN_NAME = _dec('djJyYXktcGx1Z2lu')

DNS_SERVERS = ['8.8.4.4', '1.1.1.1']

log_level = logging.DEBUG if DEBUG else logging.INFO
logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger('aiohttp.access').setLevel(logging.WARNING)
logging.getLogger('aiohttp.server').setLevel(logging.WARNING)
logging.getLogger('aiohttp.client').setLevel(logging.WARNING)
logging.getLogger('aiohttp.internal').setLevel(logging.WARNING)
logging.getLogger('aiohttp.websocket').setLevel(logging.WARNING)

logger = logging.getLogger(__name__)


def is_port_available(port, host='0.0.0.0'):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def find_available_port(start_port, max_attempts=100):
    for port in range(start_port, start_port + max_attempts):
        if is_port_available(port):
            return port
    return None


async def resolve_host(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except Exception:
        pass
    for dns_server in DNS_SERVERS:
        try:
            async with aiohttp.ClientSession() as session:
                url = f'https://dns.google/resolve?name={host}&type=A'
                async with session.get(url, timeout=5) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get('Status') == 0 and data.get('Answer'):
                            for answer in data['Answer']:
                                if answer.get('type') == 1:
                                    return answer.get('data')
        except Exception:
            continue
    return host


class SessionCore:
    def __init__(self, token: str):
        self.token = token
        self.token_bytes = bytes.fromhex(token)

    async def try_a(self, ws, first_msg: bytes) -> bool:
        try:
            if len(first_msg) < 18 or first_msg[0] != 0:
                return False
            if first_msg[1:17] != self.token_bytes:
                return False
            i = first_msg[17] + 19
            if i + 3 > len(first_msg):
                return False
            port = struct.unpack('!H', first_msg[i:i+2])[0]
            i += 2
            atyp = first_msg[i]
            i += 1
            host = ''
            if atyp == 1:
                if i + 4 > len(first_msg):
                    return False
                host = '.'.join(str(b) for b in first_msg[i:i+4])
                i += 4
            elif atyp == 2:
                if i >= len(first_msg):
                    return False
                host_len = first_msg[i]
                i += 1
                if i + host_len > len(first_msg):
                    return False
                host = first_msg[i:i+host_len].decode()
                i += host_len
            elif atyp == 3:
                if i + 16 > len(first_msg):
                    return False
                host = ':'.join(f'{(first_msg[j] << 8) + first_msg[j+1]:04x}'
                                for j in range(i, i+16, 2))
                i += 16
            else:
                return False
            await ws.send_bytes(bytes([0, 0]))
            resolved_host = await resolve_host(host)
            try:
                reader, writer = await asyncio.open_connection(resolved_host, port)
                if i < len(first_msg):
                    writer.write(first_msg[i:])
                    await writer.drain()

                async def pull_loop():
                    try:
                        async for msg in ws:
                            if msg.type == aiohttp.WSMsgType.BINARY:
                                writer.write(msg.data)
                                await writer.drain()
                    except Exception:
                        pass
                    finally:
                        writer.close()
                        await writer.wait_closed()

                async def push_loop():
                    try:
                        while True:
                            data = await reader.read(4096)
                            if not data:
                                break
                            await ws.send_bytes(data)
                    except Exception:
                        pass

                await asyncio.gather(pull_loop(), push_loop())
            except Exception as e:
                if DEBUG:
                    logger.error(f"Connection error: {e}")
            return True
        except Exception as e:
            if DEBUG:
                logger.error(f"handler a error: {e}")
            return False

    async def try_b(self, ws, first_msg: bytes) -> bool:
        try:
            if len(first_msg) < 58:
                return False
            received_hash_bytes = first_msg[:56]
            hash_obj1 = hashlib.sha224()
            hash_obj1.update(self.token.encode())
            expected_hash_hex1 = hash_obj1.hexdigest()
            token_std = TOKEN
            hash_obj2 = hashlib.sha224()
            hash_obj2.update(token_std.encode())
            expected_hash_hex2 = hash_obj2.hexdigest()
            received_hash_hex = received_hash_bytes.decode('ascii', errors='ignore')
            if received_hash_hex != expected_hash_hex1 and received_hash_hex != expected_hash_hex2:
                return False
            offset = 56
            if first_msg[offset:offset+2] == b'\r\n':
                offset += 2
            cmd = first_msg[offset]
            if cmd != 1:
                return False
            offset += 1
            atyp = first_msg[offset]
            offset += 1
            host = ''
            if atyp == 1:
                host = '.'.join(str(b) for b in first_msg[offset:offset+4])
                offset += 4
            elif atyp == 3:
                host_len = first_msg[offset]
                offset += 1
                host = first_msg[offset:offset+host_len].decode()
                offset += host_len
            elif atyp == 4:
                host = ':'.join(f'{(first_msg[j] << 8) + first_msg[j+1]:04x}'
                                for j in range(offset, offset+16, 2))
                offset += 16
            else:
                return False
            port = struct.unpack('!H', first_msg[offset:offset+2])[0]
            offset += 2
            if first_msg[offset:offset+2] == b'\r\n':
                offset += 2
            resolved_host = await resolve_host(host)
            try:
                reader, writer = await asyncio.open_connection(resolved_host, port)
                if offset < len(first_msg):
                    writer.write(first_msg[offset:])
                    await writer.drain()

                async def pull_loop():
                    try:
                        async for msg in ws:
                            if msg.type == aiohttp.WSMsgType.BINARY:
                                writer.write(msg.data)
                                await writer.drain()
                    except Exception:
                        pass
                    finally:
                        writer.close()
                        await writer.wait_closed()

                async def push_loop():
                    try:
                        while True:
                            data = await reader.read(4096)
                            if not data:
                                break
                            await ws.send_bytes(data)
                    except Exception:
                        pass

                await asyncio.gather(pull_loop(), push_loop())
            except Exception as e:
                if DEBUG:
                    logger.error(f"Connection error: {e}")
            return True
        except Exception as e:
            if DEBUG:
                logger.error(f"handler b error: {e}")
            return False

    async def try_c(self, ws, first_msg: bytes) -> bool:
        try:
            if len(first_msg) < 7:
                return False
            offset = 0
            atyp = first_msg[offset]
            offset += 1
            host = ''
            if atyp == 1:
                if offset + 4 > len(first_msg):
                    return False
                host = '.'.join(str(b) for b in first_msg[offset:offset+4])
                offset += 4
            elif atyp == 3:
                if offset >= len(first_msg):
                    return False
                host_len = first_msg[offset]
                offset += 1
                if offset + host_len > len(first_msg):
                    return False
                host = first_msg[offset:offset+host_len].decode()
                offset += host_len
            elif atyp == 4:
                if offset + 16 > len(first_msg):
                    return False
                host = ':'.join(f'{(first_msg[j] << 8) + first_msg[j+1]:04x}'
                                for j in range(offset, offset+16, 2))
                offset += 16
            else:
                return False
            if offset + 2 > len(first_msg):
                return False
            port = struct.unpack('!H', first_msg[offset:offset+2])[0]
            offset += 2
            resolved_host = await resolve_host(host)
            try:
                reader, writer = await asyncio.open_connection(resolved_host, port)
                if offset < len(first_msg):
                    writer.write(first_msg[offset:])
                    await writer.drain()

                async def pull_loop():
                    try:
                        async for msg in ws:
                            if msg.type == aiohttp.WSMsgType.BINARY:
                                writer.write(msg.data)
                                await writer.drain()
                    except Exception:
                        pass
                    finally:
                        writer.close()
                        await writer.wait_closed()

                async def push_loop():
                    try:
                        while True:
                            data = await reader.read(4096)
                            if not data:
                                break
                            await ws.send_bytes(data)
                    except Exception:
                        pass

                await asyncio.gather(pull_loop(), push_loop())
            except Exception as e:
                if DEBUG:
                    logger.error(f"Connection error: {e}")
            return True
        except Exception as e:
            if DEBUG:
                logger.error(f"handler c error: {e}")
            return False


async def ws_route(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    token_hex = TOKEN.replace('-', '')
    path = request.path
    if f'/{CHANNEL_PATH}' not in path:
        await ws.close()
        return ws
    core = SessionCore(token_hex)
    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=5)
        if first_msg.type != aiohttp.WSMsgType.BINARY:
            await ws.close()
            return ws
        msg_data = first_msg.data
        if len(msg_data) > 17 and msg_data[0] == 0:
            if await core.try_a(ws, msg_data):
                return ws
        if len(msg_data) >= 58:
            if await core.try_b(ws, msg_data):
                return ws
        if len(msg_data) > 0 and msg_data[0] in (1, 3, 4):
            if await core.try_c(ws, msg_data):
                return ws
        await ws.close()
    except asyncio.TimeoutError:
        await ws.close()
    except Exception as e:
        if DEBUG:
            logger.error(f"WS handler error: {e}")
        await ws.close()
    return ws


async def page_route(request):
    if request.path == '/':
        try:
            with open('index.html', 'r', encoding='utf-8') as f:
                content = f.read()
            return web.Response(text=content, content_type='text/html')
        except Exception:
            return web.Response(text='Hello world!', content_type='text/html')
    elif request.path == f'/{FEED_PATH}':
        label_part = LABEL or ''
        sec_param = 'tls' if UseTls == 'tls' else 'none'
        sec_suffix = 'tls;' if UseTls == 'tls' else ''
        link_a = f"{SCHEME_A}{TOKEN}@{CurrentHost}:{CurrentPort}?encryption=none&security={sec_param}&sni={CurrentHost}&fp=chrome&type=ws&host={CurrentHost}&path=%2F{CHANNEL_PATH}#{label_part}"
        link_b = f"{SCHEME_B}{TOKEN}@{CurrentHost}:{CurrentPort}?security={sec_param}&sni={CurrentHost}&fp=chrome&type=ws&host={CurrentHost}&path=%2F{CHANNEL_PATH}#{label_part}"
        method_pass = base64.b64encode(f"none:{TOKEN}".encode()).decode()
        link_c = f"{SCHEME_C}{method_pass}@{CurrentHost}:{CurrentPort}?plugin={PLUGIN_NAME};mode%3Dwebsocket;host%3D{CurrentHost};path%3D%2F{CHANNEL_PATH};{sec_suffix}sni%3D{CurrentHost};skip-cert-verify%3Dtrue;mux%3D0#{label_part}"
        payload = f"{link_a}\n{link_b}\n{link_c}"
        body = base64.b64encode(payload.encode()).decode()
        return web.Response(text=body + '\n', content_type='text/plain')
    return web.Response(status=404, text='Not Found\n')


async def main():
    actual_port = PORT
    if not is_port_available(actual_port):
        logger.warning(f"Port {actual_port} is already in use, finding available port...")
        new_port = find_available_port(actual_port + 1)
        if new_port:
            actual_port = new_port
            logger.info(f"Using port {actual_port} instead of {PORT}")
        else:
            logger.error("No available ports found")
            sys.exit(1)
    app = web.Application()
    app.router.add_get('/', page_route)
    app.router.add_get(f'/{FEED_PATH}', page_route)
    app.router.add_get(f'/{CHANNEL_PATH}', ws_route)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', actual_port)
    await site.start()
    logger.info(f"server is running on port {actual_port}")
    try:
        await asyncio.Future()
    except KeyboardInterrupt:
        pass
    finally:
        await runner.cleanup()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped by user")