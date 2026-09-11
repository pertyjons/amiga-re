import json, hashlib, os, struct

ROOT = "crates/amiga-project/fixtures/contract"
MEDIA = f"{ROOT}/original"
os.makedirs(MEDIA, exist_ok=True)

def sha(b): return hashlib.sha256(b).hexdigest()

# --- synthetic media ---------------------------------------------------------
def hunk_executable(code_words, data_bytes, reloc=None):
    """A minimal two-hunk HUNK executable: CODE then DATA."""
    code = bytes(code_words)
    data = bytes(data_bytes)
    cw, dw = len(code)//4, len(data)//4
    out = b""
    for word in (0x03f3, 0, 2, 0, 1, cw, dw):
        out += struct.pack(">I", word)
    out += struct.pack(">I", 0x03e9) + struct.pack(">I", cw) + code
    if reloc:
        out += struct.pack(">I", 0x03ec) + struct.pack(">I", len(reloc)) + struct.pack(">I", 1)
        for offset in reloc:
            out += struct.pack(">I", offset)
        out += struct.pack(">I", 0)
    out += struct.pack(">I", 0x03f2)
    out += struct.pack(">I", 0x03e9) + struct.pack(">I", dw) + data
    out += struct.pack(">I", 0x03f2)
    return out

# Module A: init_graphics opens a library then returns; a relocation into hunk 1.
CODE_A = [
    0x2c,0x78,0x00,0x04,        # 0x00 MOVEA.L 4.W,A6        (ExecBase)
    0x43,0xf9,0x00,0x00,0x00,0x00,  # 0x04 LEA $0.L,A1       (reloc -> hunk1+0)
    0x4e,0xae,0xfd,0xd8,        # 0x0a JSR (-552,A6)         (OpenLibrary)
    0x4e,0x75,                  # 0x0e RTS
    0x4e,0x71,0x4e,0x75,        # 0x10 NOP ; RTS
]
DATA_A = list(b"graphics.library\x00\x00\x00\x00")
MODULE_A = hunk_executable(CODE_A, DATA_A, reloc=[0x06])

# Module B: a level loader, deliberately overlapping module A's numeric offsets.
CODE_B = [0x4e,0x71, 0x61,0x02, 0x4e,0x75, 0x4e,0x75]
DATA_B = list(b"LEVEL\x00\x00\x00")
MODULE_B = hunk_executable(CODE_B, DATA_B)

def ofs_adf(volume, entries):
    """A tiny OFS volume. Not a full filesystem: the fixture proves the metadata
    can locate bytes, and the ADF reader has its own fixtures for parsing."""
    blocks = bytearray(b"\x00" * (512 * 40))
    blocks[0:4] = b"DOS\x00"
    return bytes(blocks)

# The three disks are distinguishable but structurally simple: the contract
# being proven here is the *metadata*, and amiga-adf carries its own parser
# fixtures. Each disk embeds one module so an object selector has real bytes.
def disk(tag, payload):
    image = bytearray(b"\x00" * (512 * 80))
    image[0:4] = b"DOS\x00"
    image[8:8+len(tag)] = tag
    image[1024:1024+len(payload)] = payload
    return bytes(image)

DISK1 = disk(b"DISK1", MODULE_A)
DISK2 = disk(b"DISK2", MODULE_B)
DISK3 = disk(b"DISK3", bytes(range(256)) * 4)

# A loose binary: an RGB4 palette followed by planar pixels and raw PCM.
PALETTE = b"".join(struct.pack(">H", c) for c in (0x000, 0xf00, 0x0f0, 0x00f))
PIXELS = bytes([0b1100_1100, 0b1010_1010] * 8)
PCM = bytes((i * 7) % 256 for i in range(64))
LOOSE = PALETTE + PIXELS + PCM

for name, data in [("disk1.adf", DISK1), ("disk2.adf", DISK2), ("disk3.adf", DISK3),
                   ("assets.bin", LOOSE)]:
    open(f"{MEDIA}/{name}", "wb").write(data)

# The directory source: two support files.
os.makedirs(f"{MEDIA}/installed/data", exist_ok=True)
SUPPORT = {"installed/startup": b"; startup script\n", "installed/data/levels.tbl": bytes(range(32))}
for path, data in SUPPORT.items():
    open(f"{MEDIA}/{path}", "wb").write(data)

print(json.dumps({
    "disk1": [len(DISK1), sha(DISK1)], "disk2": [len(DISK2), sha(DISK2)],
    "disk3": [len(DISK3), sha(DISK3)], "loose": [len(LOOSE), sha(LOOSE)],
    "module_a": [len(MODULE_A), sha(MODULE_A)], "module_b": [len(MODULE_B), sha(MODULE_B)],
    "palette": [len(PALETTE), sha(PALETTE)], "pixels": [len(PIXELS), sha(PIXELS)],
    "pcm": [len(PCM), sha(PCM)],
    "support": {p: [len(d), sha(d)] for p, d in SUPPORT.items()},
}, indent=2))
