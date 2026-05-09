# SiliconSignature — AUTOMATIC1111 WebUI Script

Automatic signing script for [AUTOMATIC1111 Stable Diffusion WebUI](https://github.com/AUTOMATIC1111/stable-diffusion-webui). Every image you generate gets an unforgeable ASIC-bound watermark.

## 🎯 What It Does

After each image generation:
1. Takes the generated PIL image
2. Computes SHA-256 hash of pixel bytes
3. Generates ASIC-bound nonce via proof-of-work
4. Embeds Reed-Solomon protected signature in LSB
5. Saves the signed image alongside the original

## 📦 Installation

1. Copy `silicon_signature.py` to your WebUI scripts folder:
   ```bash
   cp silicon_signature.py /path/to/stable-diffusion-webui/scripts/
   ```

2. Restart the WebUI

3. Find **SiliconSignature** in the Scripts dropdown

## 🚀 Usage

In the WebUI:
1. Go to **txt2img** or **img2img** tab
2. In the **Script** dropdown, select: `SiliconSignature`
3. Configure options:
   - **Creator ID**: Your name/handle (optional)
   - **Auto-sign**: Enable/disable automatic signing
   - **ASIC mode**: Use real hardware (default: software mode)
4. Generate images as normal
5. Signed images are saved with `_signed` suffix

## ⚙️ Options

| Option | Default | Description |
|--------|---------|-------------|
| Creator ID | `webui_user` | Identifier embedded in signature |
| Auto-sign | `Enabled` | Sign every generation automatically |
| ASIC mode | `Disabled` | Use real ASIC hardware (requires Antminer S9) |
| Redundancy | `5` | Reed-Solomon redundancy copies |
| Output suffix | `_signed` | Filename suffix for signed images |

## 🔍 Verify a Signed Image

Use the standalone verifier:
```bash
python verify_silicon_art.py signed_image.png
```

Or visit: https://agnuxo1.github.io/siliconsignature-web/

## 🏗️ How It Works

```
[Prompt] → [WebUI Generation] → [SiliconSignature Script] → [Signed Output]
                                    ↓
                              SHA-256 Hash
                              ASIC PoW Nonce
                              Reed-Solomon ECC
                              LSB Embedding (5×)
```

## 📁 Files

| File | Purpose |
|------|---------|
| `silicon_signature.py` | WebUI script — auto-sign after generation |

## 🔗 Links

- 🌐 Web App: https://agnuxo1.github.io/siliconsignature-web/
- 🔏 Main Repo: https://github.com/Agnuxo1/Secure_image_generation_with_ASIC_signature
- 🏠 Project Hub: https://p2pclaw.com

## 📝 License

MIT — Francisco Angulo de Lafuente (@Agnuxo1)

**Part of the P2PCLAW Ecosystem**
