"""QLoRA training of the orchestrator adapter (docs/05, step 6).

Runs on a temporary GPU machine (Colab, Kaggle, a rented instance), never on
the CyberCore host. Needs only the exported dataset directory:

    pip install -r training/requirements.txt
    python training/train_qlora.py --dataset data/training/v1 --output adapters/v1
    python training/train_qlora.py --dataset data/training/v1 --dry-run   # no GPU needed

The dataset manifest is verified first: a file whose hash does not match is
never trained on. Loss is computed only on the assistant answer
(conversational prompt/completion format).
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE_MODEL = "Qwen/Qwen3.5-9B"
# Qwen3.5 is multimodal and hybrid (linear + full attention). Adapt only the
# language model: full attention, linear attention and MLP projections. The
# vision tower and the multi-token-prediction head stay frozen.
TARGET_MODULES = (
    r".*language_model\.layers\.\d+\.("
    r"self_attn\.(q|k|v|o)_proj"
    r"|linear_attn\.(in_proj_qkv|in_proj_z|out_proj)"
    r"|mlp\.(gate|up|down)_proj)"
)


def verify_dataset(dataset_dir: Path) -> dict:
    manifest = json.loads((dataset_dir / "manifest.json").read_text(encoding="utf-8"))
    for name, info in manifest["files"].items():
        digest = hashlib.sha256((dataset_dir / name).read_bytes()).hexdigest()
        if digest != info["sha256"]:
            raise SystemExit(f"{name}: el hash no coincide con el manifiesto; no se entrena")
    return manifest


def load_examples(path: Path) -> list[dict]:
    examples = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        messages = json.loads(line)["messages"]
        if messages[-1]["role"] != "assistant" or messages[0]["role"] != "system":
            raise SystemExit(f"{path.name}:{line_number}: formato de mensajes inesperado")
        json.loads(messages[-1]["content"])  # target must be the JSON action
        examples.append({"prompt": messages[:-1], "completion": messages[-1:]})
    return examples


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--base-model", default=BASE_MODEL)
    parser.add_argument("--epochs", type=float, default=2.0)
    parser.add_argument("--learning-rate", type=float, default=2e-4)
    parser.add_argument("--rank", type=int, default=16)
    parser.add_argument("--alpha", type=int, default=32)
    parser.add_argument("--max-length", type=int, default=4096)
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--grad-accum", type=int, default=16)
    parser.add_argument("--seed", type=int, default=20260924)
    parser.add_argument("--dry-run", action="store_true", help="Sólo valida dataset y configuración")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest = verify_dataset(args.dataset)
    train = load_examples(args.dataset / "train.jsonl")
    validation = load_examples(args.dataset / "validation.jsonl")
    print(f"Dataset {manifest['name']}: {len(train)} train, {len(validation)} validation")
    if not train:
        raise SystemExit("El split train está vacío")
    if args.dry_run:
        return 0
    if args.output is None:
        raise SystemExit("--output es obligatorio salvo con --dry-run")
    if args.output.exists():
        raise SystemExit(f"{args.output} ya existe; los adaptadores son inmutables")

    # Heavy imports only when actually training.
    import torch
    from datasets import Dataset
    from peft import LoraConfig
    from transformers import AutoModelForImageTextToText, AutoTokenizer, BitsAndBytesConfig
    from trl import SFTConfig, SFTTrainer

    if not torch.cuda.is_available():
        raise SystemExit("QLoRA necesita una GPU CUDA")

    tokenizer = AutoTokenizer.from_pretrained(args.base_model)
    model = AutoModelForImageTextToText.from_pretrained(
        args.base_model,
        quantization_config=BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True,
        ),
        dtype=torch.bfloat16,
        device_map="auto",
    )
    trainer = SFTTrainer(
        model=model,
        processing_class=tokenizer,
        train_dataset=Dataset.from_list(train),
        eval_dataset=Dataset.from_list(validation) if validation else None,
        peft_config=LoraConfig(
            r=args.rank,
            lora_alpha=args.alpha,
            lora_dropout=0.05,
            bias="none",
            task_type="CAUSAL_LM",
            target_modules=TARGET_MODULES,
        ),
        args=SFTConfig(
            output_dir=str(args.output / "checkpoints"),
            num_train_epochs=args.epochs,
            learning_rate=args.learning_rate,
            per_device_train_batch_size=args.batch_size,
            gradient_accumulation_steps=args.grad_accum,
            max_length=args.max_length,
            completion_only_loss=True,
            gradient_checkpointing=True,
            bf16=True,
            lr_scheduler_type="cosine",
            warmup_ratio=0.05,
            logging_steps=5,
            eval_strategy="epoch" if validation else "no",
            save_strategy="epoch",
            seed=args.seed,
            report_to="none",
        ),
    )
    trainer.train()
    trainer.save_model(str(args.output))

    training_manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "base_model": args.base_model,
        "dataset": manifest["name"],
        "dataset_files": manifest["files"],
        "target_modules": TARGET_MODULES,
        "hyperparameters": {
            k: v for k, v in vars(args).items() if k not in {"dataset", "output", "dry_run"}
        },
        "train_examples": len(train),
        "validation_examples": len(validation),
        "log_history": trainer.state.log_history,
        "status": "pending_evaluation",
    }
    (args.output / "training_manifest.json").write_text(
        json.dumps(training_manifest, ensure_ascii=False, indent=2, default=str) + "\n",
        encoding="utf-8",
    )
    print(f"Adaptador guardado en {args.output}; siguiente paso: evaluar (docs/05)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
