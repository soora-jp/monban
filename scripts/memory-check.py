import argparse
import asyncio
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import uuid

def bound_socket(writer):
    sock = writer.get_extra_info('socket')
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16384)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16384)
    writer.transport.set_write_buffer_limits(high=16384, low=8192)

async def dns(reader, writer):
    bound_socket(writer)
    try:
        size = struct.unpack('!H', await reader.readexactly(2))[0]
        query = await reader.readexactly(size)
        end = query.index(b'\0', 12) + 5
        qtype = struct.unpack('!H', query[end-4:end-2])[0]
        answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 0, 4) + socket.inet_aton('127.0.0.1') if qtype == 1 else b''
        response = query[:2] + struct.pack('!HHHHH', 0x8180, 1, int(bool(answer)), 0, 0) + query[12:end] + answer
        writer.write(struct.pack('!H', len(response)) + response)
        await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    finally:
        writer.close()

def dense_headers():
    lines = []
    size = 0
    for i in range(450):
        line = ('X%x: %s\r\n' % (i, 'a'*24)).encode()
        if size + len(line) > 14000:
            break
        lines.append(line)
        size += len(line)
    return b''.join(lines)

HEADERS = dense_headers()

async def upstream(reader, writer):
    bound_socket(writer)
    try:
        first = await reader.readexactly(1)
        if first == b'G':
            await reader.readuntil(b'\r\n\r\n')
            writer.write(b'HTTP/1.1 200 OK\r\n' + HEADERS + b'Transfer-Encoding: chunked\r\n\r\n1\r\nx\r\n')
            await writer.drain()
            await reader.read()
        elif first == b'P':
            for _ in range(2048):
                writer.write(b'x' * 8192)
                await writer.drain()
        else:
            writer.write(first)
            while data := await reader.read(8192):
                writer.write(data)
                await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    finally:
        writer.close()

async def main():
    parser = argparse.ArgumentParser(description='Test monban inside a temporary 128Mi user-systemd cgroup.')
    parser.add_argument('output', nargs='?', type=Path, help='Optional detailed JSON output path')
    args = parser.parse_args()
    unit = 'monban-memory-check-' + uuid.uuid4().hex[:8]
    dns_server = await asyncio.start_server(dns, '127.0.0.1', 0)
    up_server = await asyncio.start_server(upstream, '127.0.0.1', 0)
    dns_port = dns_server.sockets[0].getsockname()[1]
    up_port = up_server.sockets[0].getsockname()[1]
    address = 'memory.example.test:' + str(up_port)
    command = ['systemd-run', '--user', '--quiet', '--wait', '--pipe', '--unit='+unit,
        '--property=RuntimeMaxSec=25', '--property=TimeoutStopSec=3',
        '--property=MemoryMax=134217728', '--property=MemorySwapMax=0', '--property=MemoryAccounting=yes',
        '--setenv=GOMEMLIMIT=64MiB', os.path.abspath('bin/monban'),
        '--listen', '127.0.0.1:0', '--admin-listen', '127.0.0.1:0',
        '--max-connections', '32', '--tcp-buffer-size', '262144', '--max-header-bytes', '16384',
        '--allow', address, '--pinhole', 'memory.example.test=127.0.0.1',
        '--dns-server', '127.0.0.1:'+str(dns_port), '--header-timeout', '30s',
        '--shutdown-delay', '0', '--shutdown-timeout', '1s']
    process = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    connections = []
    samples = []
    cgroup = None
    try:
        async with asyncio.timeout(20):
            async def startup():
                while line := await process.stdout.readline():
                    try:
                        entry = json.loads(line)
                    except (ValueError, UnicodeDecodeError):
                        continue
                    if entry.get('msg') == 'proxy listening':
                        return entry['proxy'], entry['admin']
                raise RuntimeError('service exited before startup')
            proxy, admin = await asyncio.wait_for(startup(), 8)
            group = subprocess.check_output(['systemctl','--user','show',unit,'-p','ControlGroup','--value'],text=True,timeout=3).strip()
            cgroup = Path('/sys/fs/cgroup') / group.lstrip('/')
            host, port = proxy.rsplit(':', 1)
            pid = int(subprocess.check_output(['systemctl','--user','show',unit,'-p','MainPID','--value'],text=True,timeout=3))
    
            def record(phase):
                sample = {'phase':phase}
                for filename in ['memory.current','memory.peak']:
                    try: sample[filename] = int((cgroup/filename).read_text())
                    except FileNotFoundError: pass
                try:
                    status = Path('/proc')/str(pid)/'status'
                    for line in status.read_text().splitlines():
                        if line.startswith(('VmRSS:', 'VmHWM:')):
                            name, value, _ = line.split()
                            sample[name.rstrip(':')] = int(value)*1024
                except FileNotFoundError: pass
                samples.append(sample)
    
            async def connect(tunnel=False):
                reader, writer = await asyncio.open_connection(host, int(port), limit=1024)
                bound_socket(writer)
                # Retain a near-limit header while copying through a CONNECT tunnel.
                writer.write(('CONNECT '+address+' HTTP/1.1\r\nHost: '+address+'\r\nX-Pad: ').encode()+b'a'*14000+b'\r\n')
                if tunnel:
                    writer.write(b'\r\n')
                await writer.drain()
                if tunnel:
                    response = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 5)
                    if not response.startswith(b'HTTP/1.1 200'):
                        raise RuntimeError('CONNECT failed: '+response[:80].decode())
                return reader, writer
    
            async def close_all():
                for _,writer in connections:
                    writer.close()
                for _,writer in connections:
                    try: await asyncio.wait_for(writer.wait_closed(),1)
                    except (ConnectionError, asyncio.TimeoutError): pass
                connections.clear()
                await asyncio.sleep(0.2)
    
            record('baseline')
            connections.extend(await asyncio.gather(*(connect() for _ in range(32))))
            await asyncio.sleep(0.3)
            record('32 near-limit incomplete request headers')
            await close_all()
    
            async def http_stream():
                reader, writer = await asyncio.open_connection(host, int(port), limit=32768)
                bound_socket(writer)
                writer.write(('GET http://'+address+'/ HTTP/1.1\r\nHost: '+address+'\r\n').encode() + HEADERS + b'\r\n')
                await writer.drain()
                response = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 5)
                if not response.startswith(b'HTTP/1.1 200'):
                    raise RuntimeError('HTTP failed: '+response[:80].decode())
                return reader, writer
            connections.extend(await asyncio.gather(*(http_stream() for _ in range(32))))
            await asyncio.sleep(0.5)
            record('32 streaming HTTP requests with dense 14KB request and response headers')
            await close_all()
    
            connections.extend(await asyncio.gather(*(connect(True) for _ in range(32))))
            payload = b'E' * (256*1024)
            async def exchange(reader, writer):
                writer.write(payload)
                await writer.drain()
                data = await reader.readexactly(len(payload))
                if data != payload: raise RuntimeError('corrupted tunnel payload')
            await asyncio.wait_for(asyncio.gather(*(exchange(r,w) for r,w in connections)), 15)
            record('32 tunnels with 14KB headers and bidirectional traffic')
            await close_all()
    
            connections.extend(await asyncio.gather(*(connect(True) for _ in range(32))))
            for _,writer in connections:
                writer.write(b'P')
            await asyncio.gather(*(writer.drain() for _,writer in connections))
            for _ in range(40):
                record('32 backpressured tunnels')
                if process.returncode is not None: break
                await asyncio.sleep(0.05)
            events = (cgroup/'memory.events').read_text() if cgroup.exists() else 'unit no longer exists'
            result = {'unit':unit,'samples':samples,'memory.events':events,'process_returncode':process.returncode}
            phases = {}
            for sample in samples:
                peak = sample.get('memory.peak', 0)
                phases[sample['phase']] = max(phases.get(sample['phase'], 0), peak)
            for phase, peak in phases.items():
                print(f'{phase}: cgroup peak {peak / 1048576:.2f} MiB')
            print(events.strip())
            if args.output:
                args.output.write_text(json.dumps(result, indent=2) + '\n')
            counters = {}
            for line in events.splitlines():
                fields = line.split()
                if len(fields) == 2 and fields[1].isdigit():
                    counters[fields[0]] = int(fields[1])
            if process.returncode is not None or any(counters.get(key, 1) != 0 for key in ('max', 'oom', 'oom_kill')):
                raise RuntimeError('128Mi memory check failed')
            await close_all()
    finally:
        for _,writer in connections: writer.close()
        try:
            subprocess.run(['systemctl','--user','stop',unit],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
        except subprocess.TimeoutExpired:
            subprocess.run(['systemctl','--user','kill','--kill-whom=all','--signal=KILL',unit],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3)
        if process.returncode is None:
            try: await asyncio.wait_for(process.wait(), 3)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
        try:
            subprocess.run(['systemctl','--user','reset-failed',unit],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3)
        except subprocess.TimeoutExpired:
            pass
        dns_server.close()
        up_server.close()
        await asyncio.wait_for(dns_server.wait_closed(),1)
        await asyncio.wait_for(up_server.wait_closed(),1)

asyncio.run(main())
