"""Train the orchestrator LoRA adapter on Modal (docs/05, step 6).

Qwen3.5 is trained with 16-bit LoRA, not 4-bit QLoRA: Unsloth's Qwen3.5 guide
advises against QLoRA for these models. 9B needs ~22 GB, so it runs on an
L40S (48 GB). Weights are cached in a Modal Volume; datasets and adapters
live in another Volume, never in git.

    # once: pip install modal && python -m modal setup
    PYTHONUTF8=1 python -m modal run training/modal_train.py --action smoke
    PYTHONUTF8=1 python -m modal run training/modal_train.py --action train --dataset v1 --adapter v1

`smoke` loads the model, renders one example with the production chat template
and runs 2 optimizer steps on a built-in toy example: it proves the image, GPU
and code work before spending credits on a real run.
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

import modal

BASE_MODEL = "Qwen/Qwen3.5-9B"
# L40S (48 GB) is comfortable; L4 (24 GB) is the tight fallback.
GPU = os.environ.get("CYBERCORE_MODAL_GPU", "L40S")
HOURS = 3600
# Container paths are POSIX even when launched from Windows.
DATA_DIR = PurePosixPath("/data")
HF_CACHE = PurePosixPath("/hf-cache")
LOCAL_DATASETS = Path(__file__).resolve().parents[1] / "data" / "training"
LOCAL_ADAPTERS = Path(__file__).resolve().parents[1] / "adapters"
# Unsloth's recommended Qwen3.5 targets (language-model projections).
TARGET_MODULES = ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]

image = (
    modal.Image.debian_slim(python_version="3.12")
    .apt_install("git")
    .uv_pip_install("unsloth", "unsloth_zoo")
    # Qwen3.5 needs transformers v5 (Unsloth guide); applied last so it wins.
    .uv_pip_install("transformers>=5.0", "trl>=1.0", "datasets>=3.0")
    .env({"HF_HUB_CACHE": str(HF_CACHE), "HF_XET_HIGH_PERFORMANCE": "1"})
)
app = modal.App("cybercore-qlora", image=image)
data_volume = modal.Volume.from_name("cybercore-training", create_if_missing=True)
hf_volume = modal.Volume.from_name("cybercore-hf-cache", create_if_missing=True)
VOLUMES = {str(DATA_DIR): data_volume, str(HF_CACHE): hf_volume}

TOY_EXAMPLE = {
    "messages": [
        {"role": "system", "content": "Eres el Orquestador Defensivo de CyberCore."},
        {"role": "user", "content": "Intención del operador: ¿Qué es CyberCore?"},
        {"role": "assistant", "content": json.dumps({
            "action_type": "final_answer",
            "arguments": None,
            "final_summary": "CyberCore es una plataforma defensiva con control de alcance.",
            "thought": "Pregunta conceptual; no hace falta ninguna herramienta.",
            "tool": None,
        }, ensure_ascii=False, sort_keys=True)},
    ]
}


def verify_manifest(dataset_dir: Path) -> dict:
    manifest = json.loads((dataset_dir / "manifest.json").read_text(encoding="utf-8"))
    for name, info in manifest["files"].items():
        digest = hashlib.sha256((dataset_dir / name).read_bytes()).hexdigest()
        if digest != info["sha256"]:
            raise RuntimeError(f"{name}: el hash no coincide con el manifiesto; no se entrena")
    return manifest


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def to_prompt_completion(examples: list[dict], tokenizer) -> list[dict]:
    """Render with the production template (thinking off, as llama.cpp serves it)."""
    rows = []
    for example in examples:
        messages = example["messages"]
        if messages[-1]["role"] != "assistant":
            raise ValueError("Cada ejemplo debe terminar en la respuesta del asistente")
        json.loads(messages[-1]["content"])
        prompt = tokenizer.apply_chat_template(
            messages[:-1], tokenize=False, add_generation_prompt=True, enable_thinking=False
        )
        rows.append({"prompt": prompt, "completion": messages[-1]["content"] + tokenizer.eos_token})
    return rows


@app.function(gpu=GPU, volumes=VOLUMES, timeout=6 * HOURS)
def train(
    dataset: str | None,
    adapter: str,
    epochs: float = 2.0,
    learning_rate: float = 2e-4,
    rank: int = 16,
    max_length: int = 4096,
    max_steps: int = -1,
) -> dict:
    from unsloth import FastLanguageModel  # must be imported before trl/transformers

    import torch
    from datasets import Dataset
    from trl import SFTConfig, SFTTrainer

    data_dir = Path(str(DATA_DIR))  # runs on Linux: a concrete path
    output = data_dir / "adapters" / adapter
    if output.exists():
        raise RuntimeError(f"{output} ya existe; los adaptadores son inmutables")
    if dataset is None:
        manifest = {"name": "toy", "files": {}}
        train_examples, validation_examples = [TOY_EXAMPLE], []
    else:
        dataset_dir = data_dir / "datasets" / dataset
        manifest = verify_manifest(dataset_dir)
        train_examples = read_jsonl(dataset_dir / "train.jsonl")
        validation_examples = read_jsonl(dataset_dir / "validation.jsonl")
    if not train_examples:
        raise RuntimeError("El split train está vacío")

    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=BASE_MODEL,
        max_seq_length=max_length,
        load_in_4bit=False,
        load_in_16bit=True,
        full_finetuning=False,
    )
    model = FastLanguageModel.get_peft_model(
        model,
        r=rank,
        target_modules=TARGET_MODULES,
        lora_alpha=rank,
        lora_dropout=0,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=20260924,
        max_seq_length=max_length,
    )
    train_rows = to_prompt_completion(train_examples, tokenizer)
    validation_rows = to_prompt_completion(validation_examples, tokenizer)
    print("Ejemplo renderizado:\n", train_rows[0]["prompt"][-400:], train_rows[0]["completion"][:200])

    trainer = SFTTrainer(
        model=model,
        processing_class=tokenizer,
        train_dataset=Dataset.from_list(train_rows),
        eval_dataset=Dataset.from_list(validation_rows) if validation_rows else None,
        args=SFTConfig(
            output_dir=str(output / "checkpoints"),
            max_length=max_length,
            completion_only_loss=True,  # loss only on the assistant JSON answer
            num_train_epochs=epochs,
            max_steps=max_steps,
            learning_rate=learning_rate,
            per_device_train_batch_size=1,
            gradient_accumulation_steps=8,
            warmup_steps=5,
            lr_scheduler_type="cosine",
            optim="adamw_8bit",
            logging_steps=1,
            eval_strategy="epoch" if validation_rows else "no",
            save_strategy="no",
            seed=20260924,
            bf16=torch.cuda.is_bf16_supported(),
            report_to="none",
            dataset_num_proc=1,
        ),
    )
    stats = trainer.train()
    model.save_pretrained(str(output))
    tokenizer.save_pretrained(str(output))

    summary = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "base_model": BASE_MODEL,
        "method": "LoRA 16-bit (Unsloth)",
        "gpu": GPU,
        "dataset": manifest["name"],
        "dataset_files": manifest["files"],
        "target_modules": TARGET_MODULES,
        "hyperparameters": {
            "epochs": epochs, "learning_rate": learning_rate, "rank": rank,
            "max_length": max_length, "max_steps": max_steps,
        },
        "train_examples": len(train_rows),
        "validation_examples": len(validation_rows),
        "train_loss": stats.training_loss,
        "log_history": trainer.state.log_history,
        "status": "pending_evaluation",
    }
    (output / "training_manifest.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8"
    )
    data_volume.commit()
    return summary


def first_json_object(text: str) -> dict | None:
    """The base model is not grammar-constrained here; take its first JSON object."""
    start = text.find("{")
    while start != -1:
        try:
            value, _ = json.JSONDecoder().raw_decode(text[start:])
            return value if isinstance(value, dict) else None
        except json.JSONDecodeError:
            start = text.find("{", start + 1)
    return None


def compare_action(predicted: dict | None, expected: dict) -> dict[str, bool]:
    """Structural agreement with the reviewed answer (free text is not graded)."""
    if predicted is None or predicted.get("action_type") not in ("call_tool", "final_answer"):
        return {"valid": False, "action_type": False, "tool": False, "target": False}
    checks = {"valid": True, "action_type": predicted["action_type"] == expected["action_type"]}
    if expected["action_type"] == "call_tool":
        args = predicted.get("arguments") or {}
        checks["tool"] = checks["action_type"] and predicted.get("tool") == expected["tool"]
        checks["target"] = checks["tool"] and args.get("target") == expected["arguments"].get("target")
    else:
        checks["tool"] = checks["target"] = checks["action_type"]
    return checks


@app.function(gpu=GPU, volumes=VOLUMES, timeout=2 * HOURS)
def evaluate(dataset: str, adapter: str, split: str = "test", max_new_tokens: int = 768) -> dict:
    """Base model vs base+adapter on a held-out split, same prompt rendering."""
    from unsloth import FastLanguageModel

    import torch

    data_dir = Path(str(DATA_DIR))
    dataset_dir = data_dir / "datasets" / dataset
    verify_manifest(dataset_dir)
    examples = read_jsonl(dataset_dir / f"{split}.jsonl")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=str(data_dir / "adapters" / adapter),
        max_seq_length=4096,
        load_in_4bit=False,
        load_in_16bit=True,
    )
    FastLanguageModel.for_inference(model)

    def generate(messages: list[dict]) -> str:
        prompt = tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True, enable_thinking=False
        )
        inputs = tokenizer(text=prompt, return_tensors="pt").to("cuda")
        with torch.no_grad():
            output = model.generate(**inputs, max_new_tokens=max_new_tokens, do_sample=False)
        return tokenizer.decode(output[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)

    rows = []
    for example in examples:
        messages = example["messages"]
        expected = json.loads(messages[-1]["content"])
        with model.disable_adapter():
            base_text = generate(messages[:-1])
        adapter_text = generate(messages[:-1])
        rows.append({
            "meta": example["meta"],
            "expected": expected,
            "base": {"text": base_text, "checks": compare_action(first_json_object(base_text), expected)},
            "adapter": {"text": adapter_text, "checks": compare_action(first_json_object(adapter_text), expected)},
        })

    def rate(model_name: str, check: str) -> float:
        return sum(row[model_name]["checks"][check] for row in rows) / len(rows)

    report = {
        "dataset": dataset,
        "adapter": adapter,
        "split": split,
        "examples": len(rows),
        "summary": {
            name: {check: rate(name, check) for check in ("valid", "action_type", "tool", "target")}
            for name in ("base", "adapter")
        },
        "rows": rows,
    }
    out = data_dir / "adapters" / adapter / f"eval_{dataset}_{split}.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    data_volume.commit()
    return report


@app.local_entrypoint()
def main(action: str = "smoke", dataset: str = "", adapter: str = "", split: str = "test"):
    if action == "evaluate":
        if not dataset or not adapter:
            raise SystemExit("Uso: --action evaluate --dataset <nombre> --adapter <nombre> [--split test]")
        report = evaluate.remote(dataset, adapter, split)
        target = LOCAL_ADAPTERS / adapter / f"eval_{dataset}_{split}.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({k: report[k] for k in ("dataset", "adapter", "split", "examples", "summary")}, indent=2))
        return
    if action == "smoke":
        name = f"smoke-{datetime.now(timezone.utc):%Y%m%d%H%M%S}"
        summary = train.remote(None, name, max_steps=2, max_length=1024)
        print(json.dumps({k: summary[k] for k in ("train_loss", "train_examples", "status")}, indent=2))
        return
    if action != "train" or not dataset or not adapter:
        raise SystemExit("Uso: --action smoke | --action train --dataset <nombre> --adapter <nombre>")

    local = LOCAL_DATASETS / dataset
    verify_manifest(local)
    with data_volume.batch_upload(force=True) as batch:
        batch.put_directory(str(local), f"/datasets/{dataset}")
    summary = train.remote(dataset, adapter)
    print(json.dumps({k: v for k, v in summary.items() if k != "log_history"}, indent=2, default=str))

    target = LOCAL_ADAPTERS / adapter
    target.mkdir(parents=True, exist_ok=False)
    for entry in data_volume.listdir(f"/adapters/{adapter}"):
        if entry.type == modal.volume.FileEntryType.FILE:
            with (target / Path(entry.path).name).open("wb") as handle:
                for chunk in data_volume.read_file(entry.path):
                    handle.write(chunk)
    print(f"Adaptador descargado en {target}; siguiente paso: evaluar (docs/05)")
