"""
Networking Module
Handles async network communication with the server.
"""

import asyncio
import threading
import queue
import json
import struct
from src.common.logger_config import setup_logger

log = setup_logger(__name__)

HOST = '127.0.0.1'
PORT = 8888


class NetworkThread(threading.Thread):
    def __init__(self, incoming_queue, outgoing_queue):
        super().__init__()
        self.incoming_queue = incoming_queue
        self.outgoing_queue = outgoing_queue
        self.loop = None
        self.reader = None
        self.writer = None
        self.running = True
        self.connected = False

    def run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.main_loop())

    async def main_loop(self):
        try:
            self.reader, self.writer = await asyncio.open_connection(HOST, PORT)
            self.connected = True
            self.incoming_queue.put({'action': 'status', 'status': 'connected', 'message': f'Conectado a {HOST}:{PORT}'})
            
            # Start receive task
            receive_task = asyncio.create_task(self.receive_loop())
            
            # Send loop
            while self.running:
                try:
                    # Non-blocking get from queue
                    msg = self.outgoing_queue.get_nowait()
                    await self.send_json(msg)
                except queue.Empty:
                    await asyncio.sleep(0.1)
            
            # Cleanup
            receive_task.cancel()
            try:
                await receive_task
            except asyncio.CancelledError:
                pass
        except Exception as e:
            log.error(f"Network error: {e}")
            self.incoming_queue.put({'action': 'status', 'status': 'disconnected', 'message': str(e)})

    async def receive_loop(self):
        try:
            while self.running:
                length_bytes = await self.reader.readexactly(4)
                length = struct.unpack('!I', length_bytes)[0]
                data = await self.reader.readexactly(length)
                message = json.loads(data.decode('utf-8'))
                self.incoming_queue.put(message)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            log.error(f"Receive error: {e}")

    async def send_json(self, data):
        try:
            payload = json.dumps(data).encode('utf-8')
            length = struct.pack('!I', len(payload))
            self.writer.write(length + payload)
            await self.writer.drain()
        except Exception as e:
            log.error(f"Send error: {e}")

    def stop(self):
        self.running = False
