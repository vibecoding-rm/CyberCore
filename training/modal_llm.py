"""Serve the production GGUF with llama.cpp on a Modal GPU (optional, temporary).

Used to collect orchestrator traces faster than on the local CPU: CyberCore
keeps running locally (policy, broker, mock tools, trace store) and only the
model calls go to this endpoint. It serves exactly the production file,
checked by SHA-256, with the same llama.cpp server and context size, and it
requires an API key.

    # once: create the key secret (the value never goes into git)
    python -m modal secret create cybercore-llm LLAMA_API_KEY=<random>
    PYTHONUTF8=1 python -m modal run training/modal_llm.py      # download + verify
    PYTHONUTF8=1 python -m modal deploy training/modal_llm.py   # start the endpoint
    PYTHONUTF8=1 python -m modal app stop cybercore-llm --yes   # stop when done

To serve an adapter converted with `modal_train.py --action gguf`, set
CYBERCORE_SERVE_MODEL=<adapter> when deploying: it becomes a separate app
(cybercore-llm-<adapter>) reading /data/gguf/<adapter>-Q4_K_M.gguf, so the
base model and an adapter can be benchmarked side by side.
"""

import hashlib
import os
import subprocess
from pathlib import PurePosixPath

import modal

REPO = "unsloth/Qwen3.5-9B-GGUF"
FILENAME = "Qwen3.5-9B-Q4_K_M.gguf"
SHA256 = "03b74727a860a56338e042c4420bb3f04b2fec5734175f4cb9fa853daf52b7e8"
ALIAS = "qwen3.5:9b"
MODELS = PurePosixPath("/models")
DATA = PurePosixPath("/data")
# Chosen at deploy time and baked into the image environment below.
SERVE_MODEL = os.environ.get("CYBERCORE_SERVE_MODEL", "base")
PORT = 8081
# Same context as the local llama.cpp service; several slots to run
# orchestrator requests in parallel.
PARALLEL = 4
CONTEXT = 8192 * PARALLEL

app = modal.App("cybercore-llm" if SERVE_MODEL == "base" else f"cybercore-llm-{SERVE_MODEL}")
models_volume = modal.Volume.from_name("cybercore-hf-cache", create_if_missing=True)
data_volume = modal.Volume.from_name("cybercore-training", create_if_missing=True)

download_image = modal.Image.debian_slim(python_version="3.12").uv_pip_install("huggingface_hub")
server_image = (
    modal.Image.from_registry("ghcr.io/ggml-org/llama.cpp:server-cuda", add_python="3.12")
    .entrypoint([])
    .env({"CYBERCORE_SERVE_MODEL": SERVE_MODEL})
)


@app.function(image=download_image, volumes={str(MODELS): models_volume}, timeout=3600)
def download() -> str:
    from huggingface_hub import hf_hub_download

    path = hf_hub_download(REPO, FILENAME, local_dir=str(MODELS / "gguf"))
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 24), b""):
            digest.update(chunk)
    if digest.hexdigest() != SHA256:
        os.remove(path)
        raise RuntimeError(f"SHA-256 inesperado: {digest.hexdigest()}")
    models_volume.commit()
    return path


@app.function(
    image=server_image,
    gpu="L4",
    volumes={str(MODELS): models_volume, str(DATA): data_volume},
    secrets=[modal.Secret.from_name("cybercore-llm", required_keys=["LLAMA_API_KEY"])],
    scaledown_window=300,
    timeout=3 * 3600,
)
@modal.concurrent(max_inputs=PARALLEL * 2)
@modal.web_server(port=PORT, startup_timeout=600)
def serve() -> None:
    if SERVE_MODEL == "base":
        model = MODELS / "gguf" / FILENAME
    else:
        model = DATA / "gguf" / f"{SERVE_MODEL}-Q4_K_M.gguf"
    if not os.path.exists(model):
        raise RuntimeError(f"Falta el modelo {model}")
    subprocess.Popen([
        "/app/llama-server",
        "-m", str(model),
        "--alias", ALIAS,
        "--host", "0.0.0.0",
        "--port", str(PORT),
        "-c", str(CONTEXT),
        "--parallel", str(PARALLEL),
        "-ngl", "99",
        "--jinja",
        "--api-key", os.environ["LLAMA_API_KEY"],
    ])


@app.local_entrypoint()
def main() -> None:
    print("Modelo verificado en:", download.remote())
