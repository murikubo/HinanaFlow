import hashlib
import json
from pathlib import Path
import plistlib
import unittest
import xml.etree.ElementTree as ET
from reference import Decoder, encode, matches, validate_control

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / 'protocol/control.schema.json').read_text())
VECTORS = json.loads((ROOT / 'protocol/vectors.json').read_text())

class ProtocolTests(unittest.TestCase):
    def test_control_vectors(self):
        for v in VECTORS['control']:
            with self.subTest(v['name']):
                if v['valid']:
                    validate_control(v['json'].encode(), SCHEMA)
                else:
                    with self.assertRaises((ValueError, UnicodeError)):
                        validate_control(v['json'].encode(), SCHEMA)
    def test_invalid_utf8(self):
        for v in VECTORS['controlBytes']:
            with self.assertRaises((ValueError, UnicodeError)):
                validate_control(bytes.fromhex(v['hex']), SCHEMA)
    def test_frames_all_splits(self):
        for v in VECTORS['frames']:
            data = bytes.fromhex(v['hex'])
            for split in range(len(data) + 1):
                with self.subTest(v=v['name'], split=split):
                    d = Decoder()
                    try:
                        result = d.feed(data[:split]) + d.feed(data[split:]); d.finish()
                    except ValueError:
                        self.assertFalse(v['valid']); continue
                    self.assertTrue(v['valid'])
                    self.assertEqual(result, [bytes.fromhex(v['payloadHex'])])
    def test_coalesced_frames_and_bytewise_input(self):
        payloads = [v['json'].encode() for v in VECTORS['control'] if v['valid']]
        stream = b''.join(encode(p) for p in payloads)
        for step in [1, 7, len(stream)]:
            d = Decoder(); result = []
            for i in range(0, len(stream), step): result += d.feed(stream[i:i+step])
            d.finish(); self.assertEqual(result, payloads)
    def test_boundary_length(self):
        d = Decoder(); payload = b'a' * 65536
        self.assertEqual(d.feed(encode(payload)), [payload]); d.finish()
        for p in [b'', b'a' * 65537]:
            with self.assertRaises(ValueError): encode(p)
        with self.assertRaises(ValueError): validate_control(b' ' * 65537, SCHEMA)
    def test_filename_vectors_match_schema(self):
        rule = next(b['properties']['name'] for b in SCHEMA['oneOf'] if 'name' in b['properties'])
        for v in VECTORS['filenames']:
            with self.subTest(v['name']): self.assertEqual(matches(v['name'], rule), v['valid'])
    def test_hash_vectors(self):
        for v in VECTORS['sha256']:
            self.assertEqual(hashlib.sha256(bytes.fromhex(v['inputHex'])).hexdigest(), v['digest'])
    def test_pin_vector(self):
        for v in VECTORS['pins']:
            point = bytes.fromhex(v['publicKeyHex'])
            self.assertEqual(len(point), 65); self.assertEqual(point[0], 4)
            self.assertEqual(hashlib.sha256(point).hexdigest(), v['sha256'])
    def test_metadata_xml(self):
        for pattern in ['*.csproj', '*.xaml', '*.manifest', '*.xcscheme', 'AndroidManifest.xml']:
            for p in ROOT.rglob(pattern):
                if '.build' not in p.parts: ET.parse(p)
        with (ROOT/'apps/ios/Info.plist').open('rb') as f:
            info = plistlib.load(f)
        self.assertEqual(info['NSBonjourServices'],['_hinanaflow._tcp'])
        self.assertTrue(info['NSLocalNetworkUsageDescription'])
        self.assertNotIn('NSAppTransportSecurity', info)
        self.assertNotIn('UIBackgroundModes', info)


class AppleProjectTests(unittest.TestCase):
    def test_ios_signing_and_shared_package(self):
        import subprocess,sys
        if sys.platform != 'darwin': self.skipTest('plutil is a macOS project syntax check')
        project=ROOT/'apps/ios/HinanaFlow.xcodeproj/project.pbxproj'
        data=json.loads(subprocess.run(['plutil','-convert','json','-o','-',str(project)],check=True,capture_output=True).stdout)
        objects=data['objects']
        packages=[v for v in objects.values() if v['isa']=='XCLocalSwiftPackageReference']
        self.assertEqual(len(packages),1)
        self.assertEqual((project.parent.parent/packages[0]['relativePath']).resolve(),(ROOT/'packages/HinanaFlowApple').resolve())
        products=[v['productName'] for v in objects.values() if v['isa']=='XCSwiftPackageProductDependency']
        self.assertEqual(products,['FlowDiagnostics'])
        for v in objects.values():
            if v['isa']=='XCBuildConfiguration':
                b=v['buildSettings']
                if 'IPHONEOS_DEPLOYMENT_TARGET' in b: self.assertEqual(b['IPHONEOS_DEPLOYMENT_TARGET'],'18.0')
                if 'CODE_SIGN_STYLE' in b:
                    self.assertEqual(b['CODE_SIGN_STYLE'],'Automatic')
                    # Empty template or a user-selected Apple Development Team.
                    self.assertRegex(b['DEVELOPMENT_TEAM'],r'^(?:[A-Z0-9]{10})?$')
        with (ROOT/'apps/ios/HinanaFlow.entitlements').open('rb') as f:self.assertEqual(plistlib.load(f),{})
    def test_auth_vector_failure_coverage(self):
        cases=json.loads((ROOT/'protocol/apple-auth-vectors.json').read_text())['cases']
        self.assertEqual(len({c['name'] for c in cases}),len(cases))
        required={'no-OOB-no-stored-key','changed-key-despite-OOB','TLS12-rejected','no-client-identity-rejected','inactive-during-handshake','activation-does-not-reconnect'}
        self.assertLessEqual(required,{c['name'] for c in cases if not c['expectedReady']})

class FileProfileTests(unittest.TestCase):
    def test_binary_vectors_all_splits(self):
        from reference import TransferDecoder
        vectors=json.loads((ROOT/'protocol/file-vectors.json').read_text())
        for v in vectors['frames']:
            data=bytes.fromhex(v['hex'])
            for split in range(len(data)+1):
                d=TransferDecoder();accepted=True
                try: d.feed(data[:split]);d.feed(data[split:]);d.finish()
                except ValueError: accepted=False
                self.assertEqual(accepted,v['valid'],v['name'])
    def test_active_file_profile_limits(self):
        from reference import validate_file_offer
        vectors=json.loads((ROOT/'protocol/file-vectors.json').read_text())
        for v in vectors['limits']:
            m={'v':1,'id':'00000000-0000-0000-0000-000000000001','type':'fileOffer','name':'ok.bin','size':v['size'],'sha256':'0'*64}
            accepted=True
            try:validate_file_offer(json.dumps(m).encode(),SCHEMA)
            except ValueError:accepted=False
            self.assertEqual(accepted,v['allowed'])
    def test_diagnostic_fixture_hash(self):
        v=json.loads((ROOT/'protocol/file-vectors.json').read_text())['fixture']
        self.assertEqual(hashlib.sha256(bytes(range(256))*(v['size']//256)).hexdigest(),v['sha256'])

if __name__ == '__main__': unittest.main()


class SharingTests(unittest.TestCase):
    def test_unicode_profile_vectors(self):
        vectors=json.loads((ROOT/'protocol/file-sharing-vectors.json').read_text())['control']
        for v in vectors:
            with self.subTest(v['name']):
                if v['valid']: validate_control(v['json'].encode(),SCHEMA)
                else:
                    with self.assertRaises(ValueError): validate_control(v['json'].encode(),SCHEMA)

class BonjourTests(unittest.TestCase):
    def test_bonjour_metadata(self):
        with (ROOT/'apps/ios/Info.plist').open('rb') as f:info=plistlib.load(f)
        self.assertEqual(info['NSBonjourServices'],['_hinanaflow._tcp'])
        self.assertNotIn('UIBackgroundModes',info)
        with (ROOT/'apps/macos/Resources/SignedInfo.plist').open('rb') as f:info=plistlib.load(f)
        self.assertEqual(info['NSBonjourServices'],['_hinanaflow._tcp'])
    def test_bonjour_vectors_have_adversarial_coverage(self):
        v=json.loads((ROOT/'protocol/bonjour-vectors.json').read_text())
        self.assertTrue(any(':' in r['peer'] and r['valid'] for r in v['routes']))
        self.assertTrue(any(':' in r['peer'] and not r['valid'] for r in v['routes']))
        self.assertTrue(any(not r['valid'] for r in v['services']))
