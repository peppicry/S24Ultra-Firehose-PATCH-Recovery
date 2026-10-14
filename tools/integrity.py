"""Offline GPT/AVB integrity checks and original-word restoration simulation."""
import hashlib
import pathlib
import struct
import zlib

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def require_separate_output(output, inputs):
    if output is None:
        return
    output = pathlib.Path(output)
    for path in inputs:
        if path is None:
            continue
        path = pathlib.Path(path)
        if output.resolve() == path.resolve() or (output.exists() and path.exists() and output.samefile(path)):
            raise ValueError('output must not overwrite an input file')

def parse_gpt(data, sector_size=4096):
    header_start = sector_size
    if data[header_start:header_start+8] != b'EFI PART':
        raise ValueError('missing primary GPT signature')
    size, expected_crc = struct.unpack_from('<II', data, header_start+12)
    if not 92 <= size <= sector_size or header_start+size > len(data):
        raise ValueError('invalid GPT header size')
    header = bytearray(data[header_start:header_start+size])
    header[16:20] = bytes(4)
    if zlib.crc32(header) & 0xffffffff != expected_crc:
        raise ValueError('GPT header CRC mismatch')
    entries_lba = struct.unpack_from('<Q', data, header_start+72)[0]
    count, entry_size, entries_crc = struct.unpack_from('<III', data, header_start+80)
    if entry_size < 128 or entry_size % 128 or count > 16384:
        raise ValueError('invalid GPT entry parameters')
    start = entries_lba*sector_size
    entries = data[start:start+count*entry_size]
    if len(entries) != count*entry_size or zlib.crc32(entries)&0xffffffff != entries_crc:
        raise ValueError('GPT entry CRC or extent mismatch')
    partitions = {}
    for index in range(count):
        entry = entries[index*entry_size:(index+1)*entry_size]
        if not any(entry[:16]):
            continue
        name = entry[56:128].decode('utf-16le').rstrip('\0')
        first, last = struct.unpack_from('<QQ', entry, 32)
        if last < first or name in partitions:
            raise ValueError('invalid or duplicate GPT partition')
        partitions[name] = {'start_sector': first, 'end_sector': last,
                            'sector_count': last-first+1}
    return partitions

def inspect_root_vbmeta(data):
    """SHA256_RSA4096 for this case; verifies against embedded public key only."""
    if len(data) < 256 or data[:4] != b'AVB0':
        raise ValueError('missing root AVB header')
    h = data[:256]
    u64 = lambda pos: struct.unpack_from('>Q', h, pos)[0]
    algorithm = struct.unpack_from('>I', h, 28)[0]
    if algorithm != 2:
        raise ValueError('this verifier supports the observed SHA256_RSA4096 only')
    auth_size, aux_size = u64(12), u64(20)
    auth = data[256:256+auth_size]
    aux = data[256+auth_size:256+auth_size+aux_size]
    if len(auth) != auth_size or len(aux) != aux_size:
        raise ValueError('truncated AVB blocks')
    def region(block, offset, size):
        if offset+size > len(block):
            raise ValueError('AVB region outside its block')
        return block[offset:offset+size]
    key = region(aux, u64(64), u64(72))
    if len(key) != 1032 or struct.unpack_from('>I', key)[0] != 4096:
        raise ValueError('invalid AVB RSA4096 public-key structure')
    n = int.from_bytes(key[8:520], 'big')
    signature = region(auth, u64(48), u64(56))
    if len(signature) != 512 or int.from_bytes(signature,'big') >= n:
        raise ValueError('invalid RSA signature length or range')
    calculated = hashlib.sha256(h+aux).digest()
    stored_hash = region(auth, u64(32), u64(40))
    # RSA public operation and exact EMSA-PKCS1-v1_5 encoding for SHA-256.
    digest_info = bytes.fromhex('3031300d060960864801650304020105000420') + calculated
    expected_em = b'\0\1' + b'\xff'*(512-len(digest_info)-3) + b'\0' + digest_info
    decoded_em = pow(int.from_bytes(signature,'big'),65537,n).to_bytes(512,'big')
    result = {'sha256':sha256(data), 'hash_valid':stored_hash == calculated,
              'signature_valid_against_embedded_key':decoded_em == expected_em,
              'embedded_key_sha256':sha256(key),
              'flags':struct.unpack_from('>I',h,120)[0], 'hash_descriptors':[]}
    pos, end = u64(96), u64(96)+u64(104)
    if end > len(aux):
        raise ValueError('descriptor block outside AVB auxiliary block')
    while pos < end:
        if pos+16 > end:
            raise ValueError('truncated AVB descriptor')
        tag, following = struct.unpack_from('>QQ',aux,pos)
        if following%8 or pos+16+following > end:
            raise ValueError('invalid descriptor length')
        block = aux[pos:pos+16+following]
        if tag == 2:
            if len(block) < 132:
                raise ValueError('truncated hash descriptor')
            image_size, algorithm_name, name_size, salt_size, digest_size, flags = struct.unpack_from('>Q32sIIII',block,16)
            payload = region(block,132,name_size+salt_size+digest_size)
            name = payload[:name_size].decode('utf-8')
            salt = payload[name_size:name_size+salt_size]
            digest = payload[name_size+salt_size:]
            result['hash_descriptors'].append({'partition':name,'image_size':image_size,
                'algorithm':algorithm_name.split(b'\0')[0].decode('ascii'),
                'salt':salt.hex(),'digest':digest.hex(),'flags':flags})
        pos += 16+following
    return result

def verify_image_descriptor(image, descriptor):
    if descriptor['image_size'] > len(image):
        raise ValueError('descriptor image extent outside input')
    calculated = hashlib.new(descriptor['algorithm'],
        bytes.fromhex(descriptor['salt'])+image[:descriptor['image_size']]).hexdigest()
    return {'calculated_digest':calculated,'matches':calculated == descriptor['digest']}

def plan_original_words(stock, current, baseline, start_sector, sector_size=4096):
    """Return data-only plan; never transmit it or mutate input files."""
    if not (len(stock) == len(current) == len(baseline)) or len(stock)%sector_size or sector_size%8:
        raise ValueError('image lengths or alignment mismatch')
    plan = []
    for offset in range(0,len(stock),8):
        word = current[offset:offset+8]
        if word == stock[offset:offset+8]:
            continue
        if word != baseline[offset:offset+8]:
            raise ValueError('unknown current word at offset '+str(offset))
        plan.append({'image_offset':offset, 'start_sector':start_sector+offset//sector_size,
                     'byte_offset':offset%sector_size,'size_in_bytes':8,
                     'value':int.from_bytes(stock[offset:offset+8],'little')})
    return plan

def simulate(current, plan, start_sector, sector_size=4096):
    result = bytearray(current)
    seen = set()
    for item in plan:
        offset = (item['start_sector']-start_sector)*sector_size+item['byte_offset']
        if item['size_in_bytes']!=8 or offset%8 or not 0<=offset<=len(result)-8 or offset in seen:
            raise ValueError('invalid/duplicate planned word')
        if offset != item['image_offset'] or item['byte_offset'] > sector_size-8:
            raise ValueError('inconsistent plan address')
        seen.add(offset)
        result[offset:offset+8] = item['value'].to_bytes(8,'little')
    return bytes(result)
