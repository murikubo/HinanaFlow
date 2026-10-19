"""Offline conformance oracle, not a production transport or a general JSON Schema implementation."""
import json
import math
import re
import struct
import unicodedata

MAX_CONTROL = 65536

def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_key")
        result[key] = value
    return result

def reject_constant(_):
    raise ValueError("non_finite")

def matches(value, schema):
    if 'oneOf' in schema:
        return sum(matches(value, branch) for branch in schema['oneOf']) == 1
    if 'const' in schema:
        expected = schema['const']
        if isinstance(value, bool) != isinstance(expected, bool) or value != expected:
            return False
    if 'enum' in schema and value not in schema['enum']:
        return False
    typ = schema.get('type')
    if typ == 'object':
        if not isinstance(value, dict): return False
        props = schema['properties']
        if not set(schema['required']) <= value.keys(): return False
        if not schema.get('additionalProperties', True) and value.keys() - props.keys(): return False
        return all(matches(v, props[k]) for k, v in value.items())
    if typ == 'string':
        if not isinstance(value, str) or any(0xD800 <= ord(c) <= 0xDFFF for c in value): return False
        if not schema.get('minLength', 0) <= len(value) <= schema.get('maxLength', math.inf): return False
        if 'pattern' in schema and re.fullmatch(schema['pattern'], value, flags=re.ASCII) is None: return False
    if typ == 'integer':
        if isinstance(value, bool) or not isinstance(value, (int, float)): return False
        if isinstance(value, float) and (not math.isfinite(value) or not value.is_integer()): return False
        if not schema.get('minimum', -math.inf) <= value <= schema.get('maximum', math.inf): return False
    if typ == 'boolean' and not isinstance(value, bool): return False
    return True

def canonical_integer(token):
    if re.fullmatch(r'0|[1-9][0-9]*', token) is None: raise ValueError("integer_token")
    return int(token)

def validate_control(payload, schema):
    if not 1 <= len(payload) <= MAX_CONTROL: raise ValueError("size")
    text = payload.decode('utf-8', errors='strict')
    if text.startswith('\ufeff'): raise ValueError("bom")
    value = json.loads(text, object_pairs_hook=unique_pairs, parse_constant=reject_constant, parse_int=canonical_integer, parse_float=reject_constant)
    if not matches(value, schema): raise ValueError("schema")
    if value.get('type')=='fileOfferUnicode' and not shared_filename(value['name']): raise ValueError('filename_policy')
    return value

def shared_filename(name):
    if name!=unicodedata.normalize('NFC',name) or not 1<=len(name)<=120 or len(name.encode())>180: return False
    if name.startswith(('.', ' ')) or name.endswith(('.', ' ')) or '..' in name: return False
    for c in name:
        if c in '/\\:<>"|?*' or unicodedata.category(c) in {'Cc','Cf','Zl','Zp','Cs','Co','Cn'} or (c.isspace() and c!=' '):return False
    reserved={'CON','PRN','AUX','NUL','CLOCK$','CONIN$','CONOUT$'}|{p+str(i) for p in ('COM','LPT') for i in range(1,10)}|{p+c for p in ('COM','LPT') for c in '¹²³'}
    return name.split('.')[0].strip(' ').upper() not in reserved

class Decoder:
    def __init__(self):
        self.header = bytearray()
        self.body = bytearray()
        self.expected = None
    def feed(self, data):
        frames = []
        for byte in data:
            if self.expected is None:
                self.header.append(byte)
                if len(self.header) == 5:
                    kind, size = struct.unpack('>BI', self.header)
                    if kind != 1 or not 1 <= size <= MAX_CONTROL: raise ValueError("header")
                    self.expected = size
            else:
                self.body.append(byte)
                if len(self.body) == self.expected:
                    frames.append(bytes(self.body))
                    self.header.clear(); self.body.clear(); self.expected = None
        return frames
    def finish(self):
        if self.header or self.expected is not None: raise ValueError("truncated")

def encode(payload):
    if not 1 <= len(payload) <= MAX_CONTROL: raise ValueError("size")
    return struct.pack('>BI', 1, len(payload)) + payload

MAX_FILE = 10_000_000
MAX_CHUNK = 32768

def validate_file_offer(payload, schema):
    m = validate_control(payload, schema)
    if m['type'] != 'fileOffer' or not 0 <= m['size'] <= MAX_FILE:
        raise ValueError('file_profile')
    return m

class TransferDecoder:
    def __init__(self):
        self.header=bytearray(); self.body=bytearray(); self.expected=None; self.kind=None
    def feed(self, data):
        result=[]
        for byte in data:
            if self.expected is None:
                self.header.append(byte)
                if len(self.header)==5:
                    self.kind,self.expected=struct.unpack('>BI',self.header)
                    if not ((self.kind==1 and 1<=self.expected<=MAX_CONTROL) or (self.kind==2 and 25<=self.expected<=24+MAX_CHUNK)):
                        raise ValueError('file_frame')
            else:
                self.body.append(byte)
                if len(self.body)==self.expected:
                    payload=bytes(self.body)
                    if self.kind==2 and int.from_bytes(payload[16:24],'big')>MAX_FILE:
                        raise ValueError('offset')
                    result.append((self.kind,payload))
                    self.header.clear(); self.body.clear(); self.expected=None
        return result
    def finish(self):
        if self.header or self.expected is not None: raise ValueError('truncated')
