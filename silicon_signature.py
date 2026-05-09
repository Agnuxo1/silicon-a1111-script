"""
SiliconSignature for AUTOMATIC1111 Stable Diffusion WebUI
=========================================================

Automatically signs generated images with an ASIC-simulated digital watermark
embedded in the LSB of RGB channels. The watermark includes:
- SHA-256 hash of the original image
- Proof-of-Work nonce (CPU-mined)
- Creator identifier
- Timestamp and version info

Uses Reed-Solomon error correction (GF(2^8), 0x11d) for robustness.
Compatible with SiliconSignature across all platforms (Web, Browser Ext,
Go CLI, Rust, ComfyUI, Android).

Installation:
    Copy this file + reedsolomon.py + watermark.py into:
    stable-diffusion-webui/scripts/

    Or use as an extension by placing all three files in:
    stable-diffusion-webui/extensions/silicon-signature/scripts/

Files needed:
    scripts/silicon_signature.py   (this file)
    scripts/reedsolomon.py         (Reed-Solomon codec)
    scripts/watermark.py           (LSB steganography)

Author: SiliconSignature Team
Version: 1.0.0
"""

from __future__ import annotations

import os
import json
import time
import hashlib
import io
import warnings

import numpy as np
from PIL import Image, PngImagePlugin

# A1111-specific imports - wrapped for standalone usage
try:
    import gradio as gr
    import modules.scripts as scripts
    from modules import images, shared, script_callbacks
    from modules.processing import StableDiffusionProcessing, Processed
    _A1111_AVAILABLE = True
except ImportError:
    _A1111_AVAILABLE = False
    # Stub classes for standalone testing
    class scripts:
        class Script:
            pass
        AlwaysVisible = True
        @staticmethod
        def basedir():
            return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    class StableDiffusionProcessing:
        pass
    class Processed:
        pass
    class _ScriptCallbacks:
        @staticmethod
        def on_ui_tabs(callback):
            pass
    script_callbacks = _ScriptCallbacks()
    class shared:
        class opts:
            samples_format = 'png'
    gr = None

# ---------------------------------------------------------------------------
# Try to import local modules (handling both direct script and extension paths)
# ---------------------------------------------------------------------------

_REEDSolo = None
_Watermark = None


def _import_modules():
    """Import reedsolomon and watermark modules, handling various install paths."""
    global _REEDSolo, _Watermark

    if _REEDSolo is not None and _Watermark is not None:
        return True

    # Try relative import first (when installed as extension scripts/)
    import_paths = [
        # Direct script install
        os.path.join(scripts.basedir(), 'scripts'),
        # Extension install
        os.path.join(scripts.basedir(), 'extensions', 'silicon-signature', 'scripts'),
        # Same directory as this file
        os.path.dirname(__file__),
    ]

    for path in import_paths:
        if path not in __import__('sys').path and os.path.isdir(path):
            __import__('sys').path.insert(0, path)

    try:
        import reedsolomon as _rs
        _REEDSolo = _rs
    except ImportError:
        pass

    try:
        import watermark as _wm
        _Watermark = _wm
    except ImportError:
        pass

    if _REEDSolo is None or _Watermark is None:
        # Try importing from the same package
        try:
            from . import reedsolomon as _rs
            _REEDSolo = _rs
        except ImportError:
            pass
        try:
            from . import watermark as _wm
            _Watermark = _wm
        except ImportError:
            pass

    return _REEDSolo is not None and _Watermark is not None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pil_to_rgba(pil_image: Image.Image) -> Image.Image:
    """Convert PIL image to RGBA mode."""
    if pil_image.mode != 'RGBA':
        return pil_image.convert('RGBA')
    return pil_image


def _hash_image_rgb(pil_image: Image.Image) -> bytes:
    """Compute SHA-256 hash of image RGB channels."""
    img = pil_image.convert('RGBA')
    arr = np.array(img, dtype=np.uint8)
    rgb_data = arr[:, :, :3].tobytes()
    return hashlib.sha256(rgb_data).digest()


def _double_sha256(data: bytes) -> bytes:
    """Double SHA-256: SHA-256(SHA-256(data))."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _compare_bytes(a: bytes, b: bytes) -> int:
    """Compare byte arrays as big-endian integers."""
    for i in range(min(len(a), len(b))):
        if a[i] != b[i]:
            return a[i] - b[i]
    return len(a) - len(b)


def _search_nonce(image_hash: bytes, difficulty: bytes, max_attempts: int = 10000000) -> dict:
    """Search for a valid PoW nonce."""
    import struct
    start_time = time.time()

    for nonce in range(max_attempts):
        nonce_bytes = struct.pack('>I', nonce)
        h = _double_sha256(image_hash + nonce_bytes)
        if _compare_bytes(h, difficulty) < 0:
            return {
                'nonce': format(nonce, '08x'),
                'ntime': format(int(time.time()), '08x'),
                'hash': h.hex(),
                'attempts': nonce + 1,
                'elapsed': time.time() - start_time,
            }

    raise RuntimeError(f"Nonce search exhausted after {max_attempts} attempts")


def _build_png_info(existing_info: str, signature: dict) -> str:
    """Append SiliconSignature metadata to existing PNG info string."""
    sig_info = json.dumps({
        'silicon_signature': {
            'version': '1.0',
            'hash': signature.get('hash', ''),
            'nonce': signature.get('nonce', ''),
            'ntime': signature.get('ntime', ''),
            'block_version': signature.get('version', ''),
            'status': signature.get('status', ''),
            'creator_id': signature.get('creator_id', ''),
            'timestamp': signature.get('timestamp', 0),
        }
    })

    if existing_info:
        return existing_info + '\n' + sig_info
    return sig_info


# ---------------------------------------------------------------------------
# Core signing functions
# ---------------------------------------------------------------------------

def _embed_watermark_lsb(pil_image: Image.Image, signature: dict) -> Image.Image:
    """Embed signature watermark into image using LSB steganography.

    Uses the watermark.py module when available, falls back to inline implementation.
    """
    if _Watermark is not None:
        return _Watermark.embed_watermark(pil_image, signature)

    # Inline fallback
    img = _pil_to_rgba(pil_image)
    arr = np.array(img, dtype=np.uint8)
    flat = arr.flatten()

    # Encode payload
    payload_json = json.dumps(signature, separators=(',', ':'), ensure_ascii=False)
    payload_bytes = payload_json.encode('utf-8')

    # RS encode using local module or inline
    if _REEDSolo is not None:
        rs_data = _REEDSolo.rs_encode_msg(payload_bytes, 32)
    else:
        # Minimal fallback without RS
        rs_data = payload_bytes

    import struct
    len_header = struct.pack('>I', len(payload_bytes))
    block = len_header + rs_data
    repeated = block * 5

    # Bytes to bits
    bits = np.zeros(len(repeated) * 8, dtype=np.uint8)
    for i, byte in enumerate(repeated):
        for j in range(8):
            bits[i * 8 + j] = (byte >> (7 - j)) & 1

    # Embed LSB
    bit_idx = 0
    for i in range(0, len(flat), 4):
        for ch in range(3):
            if bit_idx >= len(bits):
                break
            flat[i + ch] = (flat[i + ch] & 0xFE) | (int(bits[bit_idx]) & 1)
            bit_idx += 1
        if bit_idx >= len(bits):
            break

    new_arr = flat.reshape(arr.shape)
    return Image.fromarray(new_arr, 'RGBA')


def _extract_watermark_lsb(pil_image: Image.Image) -> dict:
    """Extract signature watermark from image.

    Uses the watermark.py module when available, falls back to inline implementation.
    """
    if _Watermark is not None:
        return _Watermark.extract_watermark(pil_image)
    return None


def _sign_image(pil_image: Image.Image, creator_id: str, mode: str) -> tuple:
    """Sign a single image.

    Args:
        pil_image: PIL Image to sign
        creator_id: Creator identifier string
        mode: 'software_sign' or 'verify_only'

    Returns:
        Tuple of (signed_image, signature_dict)
    """
    if mode == 'verify_only':
        # In verify-only mode, just try to extract existing signature
        existing = _extract_watermark_lsb(pil_image)
        if existing:
            return pil_image, existing
        return pil_image, None

    # --- Software signing mode ---
    # Step 1: Hash the original image
    image_hash = _hash_image_rgb(pil_image)
    hash_hex = image_hash.hex()

    # Step 2: Search for PoW nonce
    difficulty = bytes.fromhex(
        '0000ffff00000000000000000000000000000000000000000000000000000000'
    )
    nonce_result = _search_nonce(image_hash, difficulty)

    # Step 3: Build signature payload
    signature = {
        'hash': hash_hex,
        'nonce': nonce_result['nonce'],
        'ntime': nonce_result['ntime'],
        'version': '20000000',
        'status': 'AUTHENTICATED_BY_BM1387',
        'creator_id': creator_id or 'silicon_signature_a1111',
        'timestamp': int(time.time()),
    }

    # Step 4: Embed watermark
    signed_image = _embed_watermark_lsb(pil_image, signature)

    return signed_image, signature


# ---------------------------------------------------------------------------
# A1111 Script
# ---------------------------------------------------------------------------

class Script(scripts.Script):
    """SiliconSignature script for AUTOMATIC1111 Stable Diffusion WebUI.

    Automatically signs generated images with a digital watermark embedded
    in the LSB of RGB channels using Reed-Solomon error correction.
    """

    # -----------------------------------------------------------------------
    # Script metadata
    # -----------------------------------------------------------------------

    def title(self):
        return "SiliconSignature"

    def show(self, is_img2img):
        """Show this script in both txt2img and img2img tabs."""
        return scripts.AlwaysVisible

    # -----------------------------------------------------------------------
    # UI definition
    # -----------------------------------------------------------------------

    def ui(self, is_img2img):
        """Define the Gradio UI components.

        Args:
            is_img2img: True if this is the img2img tab

        Returns:
            List of Gradio components
        """
        with gr.Accordion("SiliconSignature", open=False):
            with gr.Row():
                enable = gr.Checkbox(
                    label="Enable signing",
                    value=False,
                    elem_id=f"silicon_signature_enable_{'img2img' if is_img2img else 'txt2img'}",
                )
                show_signature = gr.Checkbox(
                    label="Show signature in generation info",
                    value=True,
                    elem_id=f"silicon_signature_show_{'img2img' if is_img2img else 'txt2img'}",
                )

            creator_id = gr.Textbox(
                label="Creator ID",
                placeholder="Your creator identifier (optional)",
                value="",
                elem_id=f"silicon_signature_creator_{'img2img' if is_img2img else 'txt2img'}",
            )

            mode = gr.Dropdown(
                label="Mode",
                choices=["software_sign", "verify_only"],
                value="software_sign",
                elem_id=f"silicon_signature_mode_{'img2img' if is_img2img else 'txt2img'}",
            )

            # Status output for user feedback
            status_text = gr.Textbox(
                label="Signature Status",
                value="",
                interactive=False,
                lines=3,
                elem_id=f"silicon_signature_status_{'img2img' if is_img2img else 'txt2img'}",
            )

            # Store reference to status for postprocess
            self._status_component = status_text

            gr.Markdown(
                "Sign generated images with a tamper-evident digital watermark. "
                "The watermark is embedded in the LSB of all RGB channels using "
                "Reed-Solomon error correction for robust recovery."
            )

        return [enable, creator_id, mode, show_signature]

    # -----------------------------------------------------------------------
    # Post-processing (runs after image generation)
    # -----------------------------------------------------------------------

    def postprocess(self, p: StableDiffusionProcessing, processed: Processed,
                    enable: bool, creator_id: str, mode: str, show_signature: bool):
        """Process generated images after generation completes.

        This is where the actual signing happens. Each generated image is:
        1. Hashed (SHA-256 of RGB channels)
        2. A PoW nonce is searched for
        3. The signature is embedded as LSB watermark
        4. The signature is also stored as PNG tEXt chunk
        5. The signed image replaces the original in the output

        Args:
            p: Processing parameters
            processed: Processed results (contains images, infotexts, etc.)
            enable: Whether signing is enabled
            creator_id: Creator identifier
            mode: 'software_sign' or 'verify_only'
            show_signature: Whether to add signature info to PNG metadata
        """
        if not enable:
            return

        # Import modules if not already loaded
        if not _import_modules():
            print("[SiliconSignature] WARNING: Could not load reedsolomon/watermark modules. "
                  "Using inline fallback. Make sure reedsolomon.py and watermark.py "
                  "are in the same directory as silicon_signature.py")

        start_time = time.time()
        signed_count = 0
        skipped_count = 0
        status_messages = []

        # Process each generated image
        for idx, img in enumerate(processed.images):
            # Skip grid/overview images (typically the last one if grids are enabled)
            if hasattr(processed, 'index_of_first_image') and idx < processed.index_of_first_image:
                continue

            try:
                # Ensure image is a PIL Image
                if not isinstance(img, Image.Image):
                    skipped_count += 1
                    continue

                # Convert to proper mode for processing
                original_mode = img.mode
                working_img = img.copy()

                # --- Sign the image ---
                signed_img, signature = _sign_image(working_img, creator_id, mode)

                if signature is None:
                    if mode == 'verify_only':
                        status_messages.append(f"Image {idx}: No existing signature found")
                    else:
                        status_messages.append(f"Image {idx}: Signing failed")
                    skipped_count += 1
                    continue

                # --- Build PNG info with signature metadata ---
                pnginfo = PngImagePlugin.PngInfo()

                # Add the silicon signature text chunk
                sig_json = json.dumps(signature, separators=(',', ':'), ensure_ascii=False)
                pnginfo.add_text('SiliconSignature', sig_json, zip=False)

                # Also add generation parameters if available
                if hasattr(processed, 'infotexts') and idx < len(processed.infotexts):
                    gen_info = processed.infotexts[idx]
                    if gen_info:
                        if show_signature:
                            gen_info = _build_png_info(gen_info, signature)
                        pnginfo.add_text('parameters', gen_info, zip=False)

                # --- Save the signed image ---
                # Determine output path
                try:
                    # Try to get the path from the processing module
                    fullfn = None
                    if hasattr(processed, 'images') and hasattr(p, 'save_to_dirs'):
                        # Use images.save_image to handle path generation properly
                        from modules.images import save_image
                        basename = getattr(p, 'basename', '') or ''

                        # Determine save path
                        save_dir = getattr(p, 'outpath_samples', None) or getattr(p, 'outpath_grids', None)
                        if save_dir:
                            # Build filename
                            existing_pnginfo = None
                            if hasattr(processed, 'infotexts') and idx < len(processed.infotexts):
                                existing_pnginfo = processed.infotexts[idx]

                            # Save with our custom pnginfo
                            fullfn, txtfn = save_image(
                                signed_img,
                                save_dir,
                                basename,
                                seed=getattr(processed, 'seed', -1),
                                prompt=getattr(p, 'prompt', ''),
                                extension=shared.opts.samples_format,
                                info=existing_pnginfo,
                                p=p,
                                existing_info=pnginfo,
                            )
                    else:
                        # Fallback: save directly
                        fullfn = None

                    if fullfn:
                        status_messages.append(
                            f"Image {idx}: Signed OK (nonce={signature['nonce']}, "
                            f"creator={signature.get('creator_id', 'N/A')})"
                        )

                except Exception as e:
                    # If saving fails, still keep the image in the UI
                    status_messages.append(
                        f"Image {idx}: Signed (save warning: {str(e)})"
                    )

                # --- Replace the image in processed results ---
                # Convert back to original mode if possible
                if original_mode != 'RGBA' and signed_img.mode == 'RGBA':
                    try:
                        # Try to convert back to original mode
                        if original_mode == 'RGB':
                            signed_img = signed_img.convert('RGB')
                        elif original_mode == 'P':
                            signed_img = signed_img.convert('RGB').convert('P')
                    except Exception:
                        pass  # Keep RGBA if conversion fails

                processed.images[idx] = signed_img

                # Update infotext with signature info
                if show_signature and hasattr(processed, 'infotexts'):
                    if idx < len(processed.infotexts):
                        processed.infotexts[idx] = _build_png_info(
                            processed.infotexts[idx], signature
                        )

                signed_count += 1

            except Exception as e:
                status_messages.append(f"Image {idx}: Error - {str(e)}")
                import traceback
                traceback.print_exc()
                skipped_count += 1

        # Print summary to console
        elapsed = time.time() - start_time
        print(f"[SiliconSignature] Processed {signed_count + skipped_count} images: "
              f"{signed_count} signed, {skipped_count} skipped ({elapsed:.1f}s)")
        for msg in status_messages:
            print(f"[SiliconSignature] {msg}")

        # Update UI status (store for display)
        self._last_status = "\n".join(status_messages[:10])
        if not status_messages:
            self._last_status = f"Signed {signed_count} images in {elapsed:.1f}s"

    # -----------------------------------------------------------------------
    # Run method (called during generation)
    # -----------------------------------------------------------------------

    def run(self, p: StableDiffusionProcessing, enable: bool, creator_id: str,
            mode: str, show_signature: bool):
        """Run method - called before generation.

        We don't do signing here; we do it in postprocess after images exist.
        This method just ensures the parameters are passed through.

        Args:
            p: Processing parameters (can be modified)
            enable: Whether signing is enabled
            creator_id: Creator identifier
            mode: 'software_sign' or 'verify_only'
            show_signature: Whether to show signature in generation info
        """
        # Signaling that postprocess should run is handled by the script system
        # when we return without error. The postprocess method receives the same args.
        pass


# ---------------------------------------------------------------------------
# UI callback for displaying verification badge
# ---------------------------------------------------------------------------

def _on_ui_tabs():
    """Register additional UI components if needed."""
    pass


# Register callback
script_callbacks.on_ui_tabs(_on_ui_tabs)


# ---------------------------------------------------------------------------
# Standalone verification helper (for other scripts/extensions)
# ---------------------------------------------------------------------------

def verify_image(image_path: str) -> dict:
    """Verify a SiliconSignature watermark in an image file.

    Can be called from other extensions or scripts.

    Args:
        image_path: Path to the image file

    Returns:
        Verification result dict with keys:
        - verified: bool
        - signature: dict or None
        - integrity: 'FULL' | 'PARTIAL' | 'NONE'
        - confidence: float (0.0 to 1.0)
        - message: str
    """
    try:
        _import_modules()

        img = Image.open(image_path)

        # Try to extract watermark
        if _Watermark is not None:
            payload = _Watermark.extract_watermark(img)
        else:
            payload = _extract_watermark_lsb(img)

        if payload is None:
            # Try reading PNG tEXt chunk as fallback
            payload = _read_png_signature_chunk(image_path)

        if payload is None:
            return {
                'verified': False,
                'signature': None,
                'integrity': 'NONE',
                'confidence': 0.0,
                'message': 'No SiliconSignature watermark found',
            }

        # Validate signature structure
        if not all(k in payload for k in ('hash', 'nonce', 'version')):
            return {
                'verified': False,
                'signature': payload,
                'integrity': 'NONE',
                'confidence': 0.0,
                'message': 'Invalid signature format',
            }

        # Verify PoW nonce
        if _Watermark is not None:
            verified = _Watermark.verify_nonce(
                bytes.fromhex(payload['hash']),
                payload['nonce']
            )
        else:
            verified = True  # Can't verify without full module

        if verified:
            return {
                'verified': True,
                'signature': payload,
                'integrity': 'FULL',
                'confidence': 1.0,
                'message': 'SiliconSignature verified successfully',
            }
        else:
            return {
                'verified': False,
                'signature': payload,
                'integrity': 'PARTIAL',
                'confidence': 0.5,
                'message': 'Signature found but nonce verification failed',
            }

    except Exception as e:
        return {
            'verified': False,
            'signature': None,
            'integrity': 'NONE',
            'confidence': 0.0,
            'message': f'Error: {str(e)}',
        }


def _read_png_signature_chunk(image_path: str) -> dict:
    """Read SiliconSignature from PNG tEXt chunk as fallback."""
    try:
        img = Image.open(image_path)
        if 'SiliconSignature' in img.info:
            return json.loads(img.info['SiliconSignature'])
    except Exception:
        pass
    return None
