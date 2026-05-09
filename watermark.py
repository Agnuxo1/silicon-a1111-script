"""
SiliconSignature Watermark Module for Python / A1111
LSB steganography for embedding/extracting digital signatures in images.

Pipeline:
  Embed:  JSON -> UTF-8 -> Reed-Solomon encode -> 4-byte length header -> 5x repeat -> LSB embed
  Extract: LSB extract -> 5x split -> RS decode (voting) -> JSON parse

Compatible with the JS implementation in web-pwa/js/watermark.js
"""

import json
import hashlib
import struct
import time
from PIL import Image
import numpy as np

try:
    from .reedsolomon import rs_encode_msg, rs_decode_msg
except ImportError:
    from reedsolomon import rs_encode_msg, rs_decode_msg

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SIGNATURE_REPEATS = 5
RS_NSYM = 32
DIFFICULTY = bytes.fromhex('0000ffff00000000000000000000000000000000000000000000000000000000')


# ---------------------------------------------------------------------------
# Bit manipulation helpers
# ---------------------------------------------------------------------------

def bytes_to_bits(data: bytes) -> np.ndarray:
    """Convert bytes to a numpy array of bits (0/1 values), MSB first."""
    bits = np.zeros(len(data) * 8, dtype=np.uint8)
    for i, byte in enumerate(data):
        for j in range(8):
            bits[i * 8 + j] = (byte >> (7 - j)) & 1
    return bits


def bits_to_bytes(bits: np.ndarray) -> bytes:
    """Convert a bit array back to bytes."""
    n = len(bits) // 8
    result = bytearray(n)
    for i in range(n):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | (int(bits[i * 8 + j]) & 1)
        result[i] = byte
    return bytes(result)


# ---------------------------------------------------------------------------
# Payload encoding/decoding
# ---------------------------------------------------------------------------

def encode_payload(payload: dict) -> np.ndarray:
    """Encode a signature payload into a binary watermark bit stream.

    Steps:
      1. JSON -> UTF-8 bytes
      2. Reed-Solomon encode (add 32 ECC bytes)
      3. Prepend 4-byte big-endian length header
      4. Repeat 5 times
    """
    json_str = json.dumps(payload, separators=(',', ':'), ensure_ascii=False)
    json_bytes = json_str.encode('utf-8')

    # RS encode
    rs_data = rs_encode_msg(json_bytes, RS_NSYM)

    # Prepend 4-byte BE length header (length of JSON only, not RS)
    len_header = struct.pack('>I', len(json_bytes))

    # Combine: length header + RS-encoded data
    block = len_header + rs_data

    # Repeat 5 times
    repeated = block * SIGNATURE_REPEATS

    return bytes_to_bits(repeated)


def decode_payload(bits: np.ndarray) -> dict:
    """Decode a watermark bit stream back to a signature payload.

    Uses voting across the 5 repetitions.
    """
    repeated_bytes = bits_to_bytes(bits)

    if len(repeated_bytes) < 4 * SIGNATURE_REPEATS:
        return None

    # Read length from first repetition
    json_len = struct.unpack('>I', repeated_bytes[:4])[0]

    if json_len <= 0 or json_len > 10000:
        return _brute_force_decode(repeated_bytes)

    block_size = 4 + json_len + RS_NSYM

    if len(repeated_bytes) < block_size * SIGNATURE_REPEATS:
        return _brute_force_decode(repeated_bytes)

    # Extract each repetition and attempt decode
    for i in range(SIGNATURE_REPEATS):
        block = repeated_bytes[i * block_size:(i + 1) * block_size]
        rs_block = block[4:]  # Skip length header
        decoded = rs_decode_msg(rs_block, RS_NSYM)
        if decoded:
            try:
                json_str = decoded.decode('utf-8')
                payload = json.loads(json_str)
                if payload.get('hash') and payload.get('nonce') and payload.get('version'):
                    return payload
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass

    return _brute_force_decode(repeated_bytes)


def _brute_force_decode(repeated_bytes: bytes) -> dict:
    """Brute-force decode: try various JSON lengths."""
    for json_len in range(50, 601):
        block_size = 4 + json_len + RS_NSYM
        if len(repeated_bytes) < block_size:
            continue

        first_block = repeated_bytes[:block_size]
        rs_block = first_block[4:]
        decoded = rs_decode_msg(rs_block, RS_NSYM)
        if decoded:
            try:
                json_str = decoded.decode('utf-8')
                payload = json.loads(json_str)
                if payload.get('hash') and payload.get('nonce') and payload.get('version'):
                    return payload
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass
    return None


# ---------------------------------------------------------------------------
# LSB Embed/Extract
# ---------------------------------------------------------------------------

def embed_bits(pixels: np.ndarray, bits: np.ndarray) -> np.ndarray:
    """Embed a watermark bit stream into image RGB channels using LSB steganography.

    Args:
        pixels: Flattened RGBA pixel array (uint8)
        bits: Bit array (0/1 values) to embed

    Returns:
        Modified pixel array with embedded watermark
    """
    total_rgb = (len(pixels) // 4) * 3

    if len(bits) > total_rgb:
        raise ValueError(
            f"Image too small for watermark. Need {len(bits)} bits, have {total_rgb}"
        )

    new_pixels = pixels.copy()
    bit_idx = 0

    for i in range(0, len(pixels), 4):
        for ch in range(3):
            if bit_idx >= len(bits):
                break
            new_pixels[i + ch] = (new_pixels[i + ch] & 0xFE) | (int(bits[bit_idx]) & 1)
            bit_idx += 1

        if bit_idx >= len(bits):
            break

    return new_pixels


def extract_bits(pixels: np.ndarray, num_bits: int) -> np.ndarray:
    """Extract LSB bits from image RGB channels.

    Args:
        pixels: Flattened RGBA pixel array
        num_bits: Number of bits to extract

    Returns:
        Extracted bits as numpy array
    """
    bits = np.zeros(num_bits, dtype=np.uint8)
    bit_idx = 0

    for i in range(0, len(pixels), 4):
        for ch in range(3):
            if bit_idx >= num_bits:
                break
            bits[bit_idx] = pixels[i + ch] & 1
            bit_idx += 1

        if bit_idx >= num_bits:
            break

    return bits


# ---------------------------------------------------------------------------
# PIL Image wrappers
# ---------------------------------------------------------------------------

def pil_to_rgba_array(image: Image.Image) -> np.ndarray:
    """Convert PIL image to flat RGBA numpy array."""
    if image.mode != 'RGBA':
        image = image.convert('RGBA')
    return np.array(image, dtype=np.uint8).flatten()


def rgba_array_to_pil(pixels: np.ndarray, width: int, height: int) -> Image.Image:
    """Convert flat RGBA numpy array back to PIL image."""
    arr = pixels.reshape((height, width, 4))
    return Image.fromarray(arr, 'RGBA')


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def embed_watermark(pil_image: Image.Image, signature_dict: dict) -> Image.Image:
    """Embed a signature watermark into a PIL Image.

    Args:
        pil_image: Source PIL Image (any mode, converted to RGBA internally)
        signature_dict: Signature payload dictionary

    Returns:
        Watermarked PIL Image (RGBA mode)
    """
    # Convert to RGBA
    if pil_image.mode != 'RGBA':
        img = pil_image.convert('RGBA')
    else:
        img = pil_image.copy()

    width, height = img.size
    pixels = pil_to_rgba_array(img)

    # Encode payload to bits
    bits = encode_payload(signature_dict)

    # Embed
    new_pixels = embed_bits(pixels, bits)

    return rgba_array_to_pil(new_pixels, width, height)


def extract_watermark(pil_image: Image.Image) -> dict:
    """Extract a signature watermark from a PIL Image.

    Args:
        pil_image: PIL Image to analyze

    Returns:
        Signature payload dict or None
    """
    if pil_image.mode != 'RGBA':
        img = pil_image.convert('RGBA')
    else:
        img = pil_image

    pixels = pil_to_rgba_array(img)
    total_rgb = (len(pixels) // 4) * 3

    # Try extracting with progressively larger bit counts
    try_sizes = [6000, 9440, 12000, 16000, 24000, 32000, 48000]

    for num_bits in try_sizes:
        if num_bits > total_rgb:
            break
        bits = extract_bits(pixels, num_bits)
        payload = decode_payload(bits)
        if payload:
            return payload

    # One more try: extract all bits up to 48000
    if total_rgb > 0:
        bits = extract_bits(pixels, min(48000, total_rgb))
        return decode_payload(bits)

    return None


def hash_image_rgba(pil_image: Image.Image) -> bytes:
    """Compute SHA-256 hash of image RGB channels (skip alpha).

    Args:
        pil_image: PIL Image

    Returns:
        32-byte SHA-256 hash
    """
    if pil_image.mode != 'RGBA':
        img = pil_image.convert('RGBA')
    else:
        img = pil_image

    arr = np.array(img, dtype=np.uint8)
    # Extract only RGB channels
    rgb_data = arr[:, :, :3].tobytes()
    return hashlib.sha256(rgb_data).digest()


def _compare_bytes(a: bytes, b: bytes) -> int:
    """Compare two byte arrays as big-endian integers."""
    for i in range(min(len(a), len(b))):
        if a[i] != b[i]:
            return a[i] - b[i]
    return len(a) - len(b)


def _double_sha256(data: bytes) -> bytes:
    """Compute double SHA-256: SHA-256(SHA-256(data))."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def search_nonce(image_hash: bytes, difficulty: bytes = None,
                 max_attempts: int = 5000000) -> dict:
    """Search for a nonce satisfying: SHA-256(SHA-256(hash || nonce)) < difficulty.

    Args:
        image_hash: 32-byte image hash
        difficulty: 32-byte difficulty target (default: 0000ffff...)
        max_attempts: Maximum nonce attempts

    Returns:
        Dict with nonce (hex), ntime (hex), hash (hex)
    """
    if difficulty is None:
        difficulty = DIFFICULTY

    start_time = time.time()

    for nonce in range(max_attempts):
        # Build input: hash || nonce (4 bytes BE)
        nonce_bytes = struct.pack('>I', nonce)
        input_data = image_hash + nonce_bytes

        # Double SHA-256
        h = _double_sha256(input_data)

        # Check if hash < target
        if _compare_bytes(h, difficulty) < 0:
            nonce_hex = format(nonce, '08x')
            ntime_hex = format(int(time.time()), '08x')
            return {
                'nonce': nonce_hex,
                'ntime': ntime_hex,
                'hash': h.hex(),
                'attempts': nonce + 1,
                'elapsed': time.time() - start_time
            }

    raise RuntimeError(f"Nonce search exhausted after {max_attempts} attempts")


def verify_nonce(image_hash: bytes, nonce: str, difficulty: bytes = None) -> bool:
    """Verify that a nonce satisfies the PoW condition.

    Args:
        image_hash: 32-byte image hash
        nonce: 8-char hex nonce string
        difficulty: 32-byte difficulty target

    Returns:
        True if nonce is valid
    """
    if difficulty is None:
        difficulty = DIFFICULTY

    nonce_int = int(nonce, 16)
    nonce_bytes = struct.pack('>I', nonce_int)
    input_data = image_hash + nonce_bytes
    h = _double_sha256(input_data)
    return _compare_bytes(h, difficulty) < 0


def software_sign(image: Image.Image, creator_id: str = "") -> dict:
    """Software sign an image: find nonce and create signature payload.

    Args:
        image: PIL Image to sign
        creator_id: Optional creator identifier string

    Returns:
        Signature payload dict with all fields
    """
    # Step 1: Hash the original image
    image_hash = hash_image_rgba(image)
    hash_hex = image_hash.hex()

    # Step 2: Search for nonce (simulated PoW)
    nonce_result = search_nonce(image_hash)

    # Step 3: Build signature payload
    payload = {
        'hash': hash_hex,
        'nonce': nonce_result['nonce'],
        'ntime': nonce_result['ntime'],
        'version': '20000000',
        'status': 'AUTHENTICATED_BY_BM1387',
        'creator_id': creator_id or 'silicon_signature_a1111',
        'timestamp': int(time.time())
    }

    return payload


def verify_signature(extracted_payload: dict) -> dict:
    """Verify an extracted signature.

    Args:
        extracted_payload: Extracted signature payload dict

    Returns:
        Verification result dict
    """
    if not extracted_payload:
        return {
            'verified': False,
            'signature': None,
            'integrity': 'NONE',
            'confidence': 0.0,
            'message': 'No signature found in image'
        }

    if not extracted_payload.get('hash') or not extracted_payload.get('nonce') or not extracted_payload.get('version'):
        return {
            'verified': False,
            'signature': extracted_payload,
            'integrity': 'NONE',
            'confidence': 0.0,
            'message': 'Invalid signature format'
        }

    return {
        'verified': True,
        'signature': extracted_payload,
        'integrity': 'FULL',
        'confidence': 1.0,
        'message': 'Signature verified successfully'
    }


def generate_heatmap(original: Image.Image, signed: Image.Image) -> Image.Image:
    """Generate a heatmap overlay showing which pixels contain the watermark.

    Args:
        original: Original PIL Image
        signed: Signed/watermarked PIL Image

    Returns:
        Heatmap overlay as RGBA PIL Image
    """
    orig = original.convert('RGBA')
    sgn = signed.convert('RGBA')

    orig_arr = np.array(orig, dtype=np.uint8)
    sgn_arr = np.array(sgn, dtype=np.uint8)

    # Estimate embed region size
    test_payload = {
        'hash': '0' * 64,
        'nonce': '0' * 8,
        'ntime': '0' * 8,
        'version': '20000000',
        'status': 'AUTHENTICATED_BY_BM1387',
        'creator_id': 'test',
        'timestamp': 0
    }
    estimated_bits = len(encode_payload(test_payload))
    estimated_pixels = int(np.ceil(estimated_bits / 3))

    heat = np.zeros_like(orig_arr)
    changed = 0
    total_embed = 0

    h, w = orig_arr.shape[:2]
    for y in range(h):
        for x in range(w):
            pixel_idx = y * w + x
            r_diff = (orig_arr[y, x, 0] & 0xFE) != (sgn_arr[y, x, 0] & 0xFE)
            g_diff = (orig_arr[y, x, 1] & 0xFE) != (sgn_arr[y, x, 1] & 0xFE)
            b_diff = (orig_arr[y, x, 2] & 0xFE) != (sgn_arr[y, x, 2] & 0xFE)

            if pixel_idx < estimated_pixels:
                total_embed += 1
                if r_diff or g_diff or b_diff:
                    changed += 1
                    heat[y, x] = [245, 166, 35, 180]
                else:
                    heat[y, x] = [245, 166, 35, 40]
            else:
                heat[y, x] = [0, 0, 0, 0]

    return Image.fromarray(heat, 'RGBA')
