# Renderer golden corpus

The corpus records the expected prompt IDs and decoded reply text from the Hugging Face reference for the pinned `llama4-chat/1` profile. Cases exercise whitespace, Unicode, text parts, empty content, role boundaries and multi-turn conversations. A difference in one token ID or display character fails the gate.

## Check the renderer

Set `VIG_RENDER_ASSETS` to a directory containing `tokenizer.json` and `tokenizer_config.json` from the F37 revision. Run from the gateway repository root.

```sh
VIG_RENDER_ASSETS=/path/to/assets make test-renderer-goldens
```

To test a renderer under review, set `RENDERER_PROJECT` to its checkout. The gate installs that checkout's locked runtime, verifies the assets and runs the whole corpus against it.

```sh
VIG_RENDER_ASSETS=/path/to/assets RENDERER_PROJECT=../renderer make test-renderer-goldens
```

Use the same assets as the serving profile. [Pinned tokenizer files](https://huggingface.co/unsloth/Llama-4-Maverick-17B-128E-Instruct/tree/86c5ecb6f2fbddf604c60120125fb202e09f2556)

## Reproduce reference outputs

`manifest.json` records the F37 file digests, reference package versions and
the digest of `chat.jsonl`. Activate an environment with those reference
versions. Run from this fixture directory.

```sh
python regenerate.py "$VIG_RENDER_ASSETS" /tmp/vig-render-goldens.jsonl
cmp chat.jsonl /tmp/vig-render-goldens.jsonl
```
