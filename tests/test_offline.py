import ast
import hashlib
import json
import pathlib
import re
import struct
import tempfile
import unittest
import zlib

from tools import case, integrity, protocol
from tools.verify_evidence import REPO, verify_archived

class StreamTests(unittest.TestCase):
    def test_actual_nop_capture_split_across_every_small_boundary(self):
        r=json.loads((REPO/'evidence/results/firehose_nop_result.json').read_text(encoding='utf-8'))
        stream=r['received_text'].encode('utf-8')
        for chunk_size in (1,7,64,512,len(stream)):
            buffer=protocol.CaptureBuffer(); nodes=[]
            for pos in range(0,len(stream),chunk_size):
                buffer.feed(stream[pos:pos+chunk_size])
                while True:
                    node=buffer.pop_xml()
                    if node is None:
                        break
                    nodes.append(node)
            responses=[dict(n.attrib) for root in nodes for n in root.iter('response')]
            self.assertEqual(responses,[{'value':'ACK','rawmode':'false'}])
            self.assertFalse(buffer.buffer)

    def test_raw_payload_can_contain_xml_delimiter_without_becoming_xml(self):
        initial=b'<data><response value="ACK" rawmode="true" /></data>'
        raw=b'ANDROID!\x00</data>\xff<?xml firmware bytes'
        final=b'<data><response value="ACK" rawmode="false" /></data>'
        buffer=protocol.CaptureBuffer(); buffer.feed(initial+raw[:5])
        protocol.require_response(dict(buffer.pop_xml().find('response').attrib),'true')
        self.assertIsNone(buffer.pop_raw(len(raw)))
        buffer.feed(raw[5:]+final)
        self.assertEqual(buffer.pop_raw(len(raw)),raw)
        protocol.require_response(dict(buffer.pop_xml().find('response').attrib),'false')
        self.assertFalse(buffer.buffer)

    def test_initial_ack_is_not_a_final_success(self):
        with self.assertRaises(ValueError):
            protocol.require_response({'value':'ACK','rawmode':'true'},'false')
        with self.assertRaises(ValueError):
            protocol.require_response({'value':'NAK','rawmode':'false'},'false')

class PlanTests(unittest.TestCase):
    def test_word_address_at_both_partition_edges_and_resume(self):
        stock=bytearray(8192); baseline=bytearray(stock)
        baseline[:8]=b'oldword!'; baseline[-8:]=b'lastold!'
        plan=integrity.plan_original_words(bytes(stock),bytes(baseline),bytes(baseline),case.START_SECTOR)
        self.assertEqual([(r['start_sector'],r['byte_offset']) for r in plan],
                         [(case.START_SECTOR,0),(case.START_SECTOR+1,4088)])
        self.assertEqual(integrity.simulate(bytes(baseline),plan,case.START_SECTOR),bytes(stock))
        partial=bytearray(baseline); partial[:8]=stock[:8]
        resumed=integrity.plan_original_words(bytes(stock),bytes(partial),bytes(baseline),case.START_SECTOR)
        self.assertEqual(len(resumed),1)
        self.assertEqual(integrity.simulate(bytes(partial),resumed,case.START_SECTOR),bytes(stock))

    def test_unknown_current_word_is_not_silently_replaced(self):
        with self.assertRaises(ValueError):
            integrity.plan_original_words(bytes(4096),b'unknown!'+bytes(4088),b'baseline'+bytes(4088),0)

    def test_invalid_duplicate_or_outside_plan_is_rejected(self):
        original=bytes(4096)
        word={'image_offset':0,'start_sector':case.START_SECTOR,'byte_offset':0,'size_in_bytes':8,'value':1}
        for plan in ([word,word],[dict(word,byte_offset=4096)],
                     [dict(word,start_sector=case.START_SECTOR-1)],
                     [dict(word,byte_offset=1,image_offset=1)]):
            with self.assertRaises(ValueError):
                integrity.simulate(original,plan,case.START_SECTOR)

    def test_unsigned_word_encoding_keeps_high_bit(self):
        stock=b'\xff'*8+bytes(4088); baseline=bytes(4096)
        plan=integrity.plan_original_words(stock,baseline,baseline,0)
        self.assertEqual(plan[0]['value'],2**64-1)
        self.assertEqual(integrity.simulate(baseline,plan,0),stock)

class IntegrityTests(unittest.TestCase):
    def test_output_cannot_overwrite_an_original_input(self):
        with tempfile.TemporaryDirectory() as directory:
            p=pathlib.Path(directory)/'original.img'; p.write_bytes(b'original')
            with self.assertRaises(ValueError):
                integrity.require_separate_output(p,[p])
            self.assertEqual(p.read_bytes(),b'original')
    @staticmethod
    def synthetic_gpt():
        data=bytearray(5*4096); h=memoryview(data)[4096:8192]
        h[:8]=b'EFI PART'; struct.pack_into('<I',h,8,0x10000)
        struct.pack_into('<I',h,12,92); struct.pack_into('<Q',h,72,2)
        struct.pack_into('<II',h,80,1,128)
        entry=memoryview(data)[8192:8320]; entry[:16]=bytes([1])*16
        struct.pack_into('<QQ',entry,32,case.START_SECTOR,case.START_SECTOR+case.SECTOR_COUNT-1)
        name='init_boot'.encode('utf-16le'); entry[56:56+len(name)]=name
        struct.pack_into('<I',h,88,zlib.crc32(entry)&0xffffffff)
        struct.pack_into('<I',h,16,zlib.crc32(h[:92])&0xffffffff)
        return bytes(data)

    def test_gpt_corruption_detected_in_header_and_entries(self):
        good=self.synthetic_gpt()
        self.assertEqual(integrity.parse_gpt(good)['init_boot']['sector_count'],2048)
        for location in (4096+24,8192+32):
            damaged=bytearray(good); damaged[location]^=1
            with self.assertRaises(ValueError):
                integrity.parse_gpt(damaged)

    def test_salted_descriptor_hash_uses_exact_image_extent(self):
        image=b'payload'+b'ignored'; salt=b'salt'
        desc={'algorithm':'sha256','image_size':7,'salt':salt.hex(),
              'digest':hashlib.sha256(salt+b'payload').hexdigest()}
        self.assertTrue(integrity.verify_image_descriptor(image,desc)['matches'])
        self.assertFalse(integrity.verify_image_descriptor(b'PAYLOADignored',desc)['matches'])

    def test_unsupported_or_truncated_avb_is_not_certified(self):
        for data in (b'AVB0',b'bad!'+bytes(252),b'AVB0'+bytes(252)):
            with self.assertRaises(ValueError):
                integrity.inspect_root_vbmeta(data)

class ArchiveTests(unittest.TestCase):
    def test_evidence_is_consistent_and_identical_value_probe_is_not_write_proof(self):
        result=verify_archived()
        self.assertEqual(result['sanitized_exports_verified'],50)
        self.assertEqual(result['recorded_total_original_words'],277635)

    def test_published_tree_contains_no_images_secrets_or_original_personal_paths(self):
        secret=re.compile(r'(?i)C:[\\/]+Users[\\/]+[^<]|/(?:Users|home)/[^<\s/]+|'
                          r'gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|'
                          r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')
        binaries={'.img','.bin','.elf','.mbn','.cpio','.zip','.tar','.md5','.7z','.rar'}
        for path in REPO.rglob('*'):
            if not path.is_file() or any(part in ('.git','__pycache__') for part in path.relative_to(REPO).parts):
                continue
            self.assertNotIn(path.suffix.lower(),binaries,path)
            self.assertIsNone(secret.search(path.read_text(encoding='utf-8')),str(path))

    def test_runnable_tools_have_no_hardware_or_network_imports(self):
        forbidden={'serial','usb','socket','requests','urllib','ctypes','subprocess'}
        for path in (REPO/'tools').glob('*.py'):
            tree=ast.parse(path.read_text(encoding='utf-8'),filename=str(path))
            for node in ast.walk(tree):
                names=[]
                if isinstance(node,ast.Import):
                    names=[a.name.split('.')[0] for a in node.names]
                elif isinstance(node,ast.ImportFrom) and node.module:
                    names=[node.module.split('.')[0]]
                self.assertFalse(set(names)&forbidden,str(path))

    def test_historical_code_is_text_and_syntax_valid_without_execution(self):
        for path in (REPO/'historical').rglob('*.py.txt'):
            ast.parse(path.read_text(encoding='utf-8'),filename=str(path))

if __name__=='__main__':
    unittest.main()
