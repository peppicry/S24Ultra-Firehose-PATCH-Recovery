"""Model XML/raw byte-stream framing offline; does not open any connection."""
import xml.etree.ElementTree as ET

class CaptureBuffer:
    def __init__(self):
        self.buffer = bytearray()

    def feed(self, data):
        self.buffer.extend(data)

    def pop_xml(self):
        end = self.buffer.find(b'</data>')
        if end < 0:
            return None
        packet = bytes(self.buffer[:end + 7])
        # Parse before consuming so malformed input cannot be silently skipped.
        root = ET.fromstring(packet.strip())
        del self.buffer[:end + 7]
        return root

    def pop_raw(self, count):
        if count < 0:
            raise ValueError('negative raw byte count')
        if len(self.buffer) < count:
            return None
        data = bytes(self.buffer[:count])
        del self.buffer[:count]
        return data

def require_response(response, rawmode):
    if response.get('value') != 'ACK' or response.get('rawmode') != rawmode:
        raise ValueError('operation not confirmed: ' + repr(response))

def extract_xml(text):
    """For text-only log fields, never for mixed raw firmware captures."""
    buffer = CaptureBuffer()
    buffer.feed(text.encode('utf-8'))
    result = []
    while True:
        root = buffer.pop_xml()
        if root is None:
            return result
        result.append(root)
