"""
Silicon Signature Script for AUTOMATIC1111 Stable Diffusion WebUI
====================================================================
Auto-signs generated images with hardware-bound proof-of-work signatures.

Installation:
1. Copy to stable-diffusion-webui/scripts/silicon_signature.py
2. Restart WebUI
3. Find "Silicon Signature" in the Scripts dropdown

Author: Francisco Angulo de Lafuente
"""

import os
import sys
import json
import requests
import hashlib
from pathlib import Path
from PIL import Image
import numpy as np

import modules.scripts as scripts
from modules import shared, script_callbacks, images
from modules.processing import Processed


class SiliconSignatureScript(scripts.Script):
    """
    Script that automatically signs generated images with Silicon signatures.
    """
    
    def title(self):
        return "🔏 Silicon Signature"
    
    def show(self, is_img2img):
        return scripts.AlwaysVisible  # Show in both txt2img and img2img
    
    def ui(self, is_img2img):
        """
        UI components for the script.
        """
        import gradio as gr
        
        with gr.Group():
            with gr.Accordion("Silicon Signature", open=False):
                enabled = gr.Checkbox(
                    label="Enable Silicon Signing",
                    value=False,
                    info="Auto-sign all generated images"
                )
                
                creator_id = gr.Textbox(
                    label="Creator ID",
                    value="sd_user",
                    info="Your identifier for the signature"
                )
                
                api_url = gr.Textbox(
                    label="API URL",
                    value="http://localhost:8000",
                    info="Silicon API endpoint"
                )
                
                api_key = gr.Textbox(
                    label="API Key",
                    value="",
                    type="password",
                    info="Optional API key"
                )
                
                watermark = gr.Checkbox(
                    label="Embed LSB Watermark",
                    value=True,
                    info="Add invisible watermark for extra verification"
                )
                
                status = gr.Textbox(
                    label="Status",
                    value="Ready",
                    interactive=False
                )
        
        return [enabled, creator_id, api_url, api_key, watermark, status]
    
    def run(self, p, enabled, creator_id, api_url, api_key, watermark, status):
        """
        This method is called after generation for img2img.
        For txt2img, we use the callback below.
        """
        if not enabled:
            return Processed(p, p.init_images, p.seed, "")
        
        # Process images
        signed_images = []
        signatures = []
        
        for i, img in enumerate(p.init_images):
            try:
                signed_img, sig = self._sign_image(
                    img, creator_id, api_url, api_key, watermark
                )
                signed_images.append(signed_img)
                signatures.append(sig)
            except Exception as e:
                print(f"[SiliconSignature] Error signing image {i}: {e}")
                signed_images.append(img)
                signatures.append({"error": str(e)})
        
        # Replace images with signed versions
        p.init_images = signed_images
        
        # Save signatures to text file
        self._save_signatures(p, signatures)
        
        return Processed(p, signed_images, p.seed, "")
    
    def _sign_image(self, image, creator_id, api_url, api_key, watermark):
        """
        Sign a single image via the Silicon API.
        """
        # Save image to temp file
        temp_path = f"/tmp/sd_silicon_{hashlib.md5(str(image).encode()).hexdigest()[:8]}.png"
        image.save(temp_path, 'PNG')
        
        try:
            with open(temp_path, 'rb') as f:
                files = {'file': f}
                data = {
                    'creator_id': creator_id,
                    'watermark': 'true' if watermark else 'false'
                }
                
                headers = {}
                if api_key:
                    headers['X-API-Key'] = api_key
                
                response = requests.post(
                    f"{api_url}/api/v1/sign",
                    files=files,
                    data=data,
                    headers=headers,
                    timeout=60
                )
                
                if response.status_code == 200:
                    # Load signed image
                    signed_path = temp_path.replace('.png', '_signed.png')
                    with open(signed_path, 'wb') as f:
                        f.write(response.content)
                    
                    signed_img = Image.open(signed_path)
                    
                    # Cleanup
                    os.remove(temp_path)
                    os.remove(signed_path)
                    
                    return signed_img, {
                        "status": "signed",
                        "creator": creator_id,
                        "api": api_url
                    }
                else:
                    raise Exception(f"API error: {response.status_code}")
                    
        except Exception as e:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise e
    
    def _save_signatures(self, p, signatures):
        """
        Save signature metadata alongside generated images.
        """
        try:
            # Find the output directory
            output_dir = p.outpath_samples or shared.opts.outdir_txt2img_samples
            
            # Create signatures file
            sig_filename = f"signatures_{p.seed}.json"
            sig_path = os.path.join(output_dir, sig_filename)
            
            with open(sig_path, 'w') as f:
                json.dump({
                    "signatures": signatures,
                    "prompt": p.prompt,
                    "seed": p.seed,
                    "model": shared.sd_model.sd_model_info if hasattr(shared.sd_model, 'sd_model_info') else "unknown"
                }, f, indent=2)
            
            print(f"[SiliconSignature] Signatures saved to: {sig_path}")
            
        except Exception as e:
            print(f"[SiliconSignature] Error saving signatures: {e}")


def postprocess_callback(params):
    """
    Callback that runs after txt2img generation.
    This is the main entry point for auto-signing.
    """
    # Check if Silicon signing is enabled in settings
    if not hasattr(shared.opts, 'silicon_enabled') or not shared.opts.silicon_enabled:
        return
    
    try:
        script = SiliconSignatureScript()
        
        for i, img in enumerate(params.images):
            signed_img, sig = script._sign_image(
                img,
                getattr(shared.opts, 'silicon_creator_id', 'sd_user'),
                getattr(shared.opts, 'silicon_api_url', 'http://localhost:8000'),
                getattr(shared.opts, 'silicon_api_key', ''),
                getattr(shared.opts, 'silicon_watermark', True)
            )
            
            # Replace image with signed version
            params.images[i] = signed_img
            
    except Exception as e:
        print(f"[SiliconSignature] Post-process error: {e}")


# Register callback
script_callbacks.on_image_saved(postprocess_callback)


# Settings UI
def on_ui_settings():
    """
    Add Silicon Signature settings to WebUI settings page.
    """
    import gradio as gr
    
    section = ('silicon', 'Silicon Signature')
    
    shared.opts.add_option(
        "silicon_enabled",
        shared.OptionInfo(
            False,
            "Auto-sign all generated images",
            section=section
        )
    )
    
    shared.opts.add_option(
        "silicon_creator_id",
        shared.OptionInfo(
            "sd_user",
            "Default Creator ID",
            section=section
        )
    )
    
    shared.opts.add_option(
        "silicon_api_url",
        shared.OptionInfo(
            "http://localhost:8000",
            "Silicon API URL",
            section=section
        )
    )
    
    shared.opts.add_option(
        "silicon_api_key",
        shared.OptionInfo(
            "",
            "API Key",
            section=section
        )
    )
    
    shared.opts.add_option(
        "silicon_watermark",
        shared.OptionInfo(
            True,
            "Embed LSB watermark",
            section=section
        )
    )


script_callbacks.on_ui_settings(on_ui_settings)


# Install instructions
INSTALL_INSTRUCTIONS = """
=== SiliconSignature for AUTOMATIC1111 ===

Installation:
  1. Copy this file to:
     stable-diffusion-webui/scripts/silicon_signature.py
  
  2. Restart WebUI
  
  3. Two ways to use:
     
     A) Per-generation (Script dropdown):
        - Go to txt2img/img2img
        - Open "Scripts" dropdown
        - Select "🔏 Silicon Signature"
        - Check "Enable"
        - Set Creator ID
        - Generate — images are auto-signed!
     
     B) Always-on (Settings):
        - Go to Settings → Silicon Signature
        - Enable "Auto-sign all generated images"
        - Set default Creator ID and API URL
        - All future generations are signed automatically

Features:
  ✅ Auto-signs every generated image
  ✅ Embeds metadata in PNG chunks
  ✅ Optional LSB watermark (invisible)
  ✅ Saves signature JSON alongside images
  ✅ Works with batches
  ✅ Compatible with all samplers

Requirements:
  - Silicon API running (default: http://localhost:8000)
  - Or use the software_mode.py standalone signer
"""

print(INSTALL_INSTRUCTIONS)
