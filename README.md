# SiliconSignature for AUTOMATIC1111 Stable Diffusion WebUI

Automatically sign generated images with a tamper-evident digital watermark embedded in the LSB of RGB channels. Compatible with SiliconSignature across all platforms (Web PWA, Browser Extension, Go CLI, Rust, ComfyUI, Android).

## Features

- **Automatic signing** after each image generation (txt2img & img2img)
- **LSB steganography** in all RGB channels for invisible watermarking
- **Reed-Solomon error correction** (GF(2^8), 0x11d) - survives compression, cropping, and noise
- **Proof-of-Work nonce** - ASIC-simulated with CPU mining
- **Dual storage** - Watermark in LSB + PNG tEXt chunk backup
- **Cross-platform verification** - Signed images can be verified by any SiliconSignature implementation

## Installation

### Method 1: Direct Script Install (Simplest)

1. Copy these three files into your WebUI `scripts/` folder:
   ```bash
   cp silicon_signature.py reedsolomon.py watermark.py \
      /path/to/stable-diffusion-webui/scripts/
   ```

2. Restart AUTOMATIC1111 WebUI

3. Look for the **"SiliconSignature"** accordion in the txt2img/img2img tabs

### Method 2: Extension Install (Recommended)

1. Navigate to your extensions directory:
   ```bash
   cd /path/to/stable-diffusion-webui/extensions
   ```

2. Create the extension folder and copy files:
   ```bash
   mkdir -p silicon-signature/scripts
   cp silicon_signature.py reedsolomon.py watermark.py silicon-signature/scripts/
   ```

3. Restart the WebUI

## Usage

### Signing Images

1. Open the **SiliconSignature** accordion in txt2img or img2img
2. Check **"Enable signing"**
3. Optionally enter your **Creator ID** (e.g., your artist name or handle)
4. Set **Mode** to `software_sign` (default)
5. Generate images as normal - they will be automatically signed

### Verifying Signed Images

1. Set **Mode** to `verify_only`
2. Generate or process an image
3. The script will check for an existing watermark and report results

### Options

| Option | Description |
|--------|-------------|
| **Enable signing** | Toggle the signing feature on/off |
| **Creator ID** | Your identifier embedded in the signature (optional) |
| **Mode** | `software_sign` to sign, `verify_only` to verify existing |
| **Show signature info** | Add signature metadata to PNG generation info |

## Technical Details

### Signature Format (SSv1)

```json
{
  "hash": "65501a37b306f5ac183848bab643350219c18111bfa97c706856b668d3bd5996",
  "nonce": "f16823b5",
  "ntime": "6964c85e",
  "version": "20000000",
  "status": "AUTHENTICATED_BY_BM1387",
  "creator_id": "optional_creator",
  "timestamp": 1715432000
}
```

### Binary Encoding Pipeline

```
JSON payload -> UTF-8 bytes -> Reed-Solomon encode (nsym=32) 
  -> 4-byte BE length header -> 5x repeat -> bit stream 
  -> LSB embed in all RGB channels (R, G, B per pixel)
```

### Reed-Solomon Parameters

- **Field**: GF(2^8) with primitive polynomial `0x11d`
- **Error correction symbols**: 32 (nsym)
- **Primitive element**: 2 (alpha = 0x02)
- **Generator**: Product of (x - alpha^i) for i = 0..31

### Proof-of-Work

- Target: `0x0000FFFF00000000000000000000000000000000000000000000000000000000`
- Algorithm: SHA-256(SHA-256(hash || nonce)) < target
- Nonce search: Sequential scan (CPU)

## Files

| File | Purpose |
|------|---------|
| `silicon_signature.py` | A1111 Script - UI and post-processing |
| `reedsolomon.py` | Reed-Solomon codec (GF(2^8), 0x11d) |
| `watermark.py` | LSB steganography embed/extract |

## Cross-Platform Compatibility

Images signed by this A1111 script can be verified by:
- [Web PWA](../web-pwa/) - Browser-based verifier
- [Browser Extension](../browser-ext/) - Right-click verify in browser
- [Go CLI](../go-cli/) - Command-line tool
- [Rust](../rust-lib/) - Native + WASM library
- [ComfyUI](../comfyui-node/) - ComfyUI custom node
- [Android](../android-app/) - Mobile app

## API for Other Scripts

Other extensions can use the verification API:

```python
# In your own A1111 extension/script:
import sys
sys.path.insert(0, 'extensions/silicon-signature/scripts')
from silicon_signature import verify_image

result = verify_image('/path/to/image.png')
print(result['verified'])   # True/False
print(result['signature'])  # Full signature dict
print(result['message'])    # Human-readable result
```

## Troubleshooting

### Script not showing in UI
- Ensure all three `.py` files are in the same `scripts/` directory
- Check the WebUI console for import errors
- Try refreshing the browser page (F5)

### "Could not load reedsolomon/watermark modules"
- This warning means the fallback mode is active (still works but slower)
- Make sure `reedsolomon.py` and `watermark.py` are in the same folder as `silicon_signature.py`

### Signing takes too long
- The PoW nonce search is CPU-intensive by design
- For batch generations, the first image takes longest (subsequent share warm cache)
- Reduce nonce search space by lowering difficulty (advanced)

## License

MIT - Part of the SiliconSignature project.
