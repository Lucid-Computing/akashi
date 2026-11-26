# Native verifier provenance

The `akashi-verify` 0.0.0 development wheel includes the offline holder CLI and the CPU verification inputs for Maverick commitment `c7982f8a090b5e47c2f04e3b10bda65600d53322480cdd8f3ded328529271f46`. The Python modules and native files are enumerated in the wheel build metadata. [Wheel contents](pyproject.toml) · [Holder installation](../../verifier/README.md#install-the-development-wheel)

## Native executable

FlashProve 0.16.0 at `9e2bdd8ff5bf9c62f18263d7dac189b0400b260c` supplies the verifier source and build script. Independent CPU build 7410 ran on x86-64 Ubuntu 24.04 with G++ 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1) and glibc 2.39. The resulting ELF was byte-identical to the binary used for F4 verification. [Pinned upstream build](https://github.com/anthropics/FlashProve/blob/9e2bdd8ff5bf9c62f18263d7dac189b0400b260c/verifier/build.sh)

To reproduce that comparison, use the same toolchain and run these commands in the pinned FlashProve checkout. Supply a fresh directory in a trusted location owned by the builder.

```sh
build_dir=$(mktemp -d)
mkdir -m 700 "$build_dir/output"
env -i PATH=/usr/bin:/bin LC_ALL=C HOME="$build_dir" \
  bash verifier/build.sh --field 2 - "$build_dir/output"
printf '%s  %s\n' 7f9efc1e86a848a3715c6cc870e465ac2a1c5e8fd1eac09e4809023de7604394 \
  "$build_dir/output/cp_verify" | sha256sum --check
```

The host must support x86 SHA extensions (`sha_ni` in Linux CPU flags). The wrapper invokes `/usr/bin/prlimit` and uses `/proc`. The ELF requests `/lib64/ld-linux-x86-64.so.2` and dynamically loads `libc.so.6`, `libm.so.6`, `libgcc_s.so.1` and `libstdc++.so.6`. Its imported symbols reach GLIBC_2.38, GLIBCXX_3.4.30 and CXXABI_1.3.9. The qualification applies to the measured Ubuntu environment. The wheel declares the platform tag `linux_x86_64`. [Hardware gate](../../tools/check_hardware.py) · [Native execution](../../verifier/proof.py)

## Public verification inputs

The commitment comparison in rebuild 7219 reproduced the public F4 key and configuration digests. The table identifies every file in the installed `verifier/native` directory. Build 7410 supplies the executable hash. The fitted configuration supplies the policy and layout hashes. FlashProve publishes the three remaining input hashes in its expected values. [Original F4 values](https://github.com/anthropics/FlashProve/blob/9e2bdd8ff5bf9c62f18263d7dac189b0400b260c/examples/maverick/expected.txt) · [Measured manifest](native/manifest.json)

| File | SHA-256 |
|---|---|
| `cp_verify` | `7f9efc1e86a848a3715c6cc870e465ac2a1c5e8fd1eac09e4809023de7604394` |
| `config/policy.txt` | `91803480b032dc993722b50d552703024f2e78a991c7a239852855177772ee0d` |
| `config/layout.txt` | `a99b964bbd3648d6e3b4007fc9370b5c70c7e9668848daa039820bc9e03e8f80` |
| `config/KL.bin` | `df29bd823d62431945c3124138ed52e1f677db9224c4196505a91663ac48ab1a` |
| `ivk/key.bin` | `178d8814def56f88fae45f273c7f70152dac887ddc9075b6aca2f895c24c7c38` |
| `ivk/leaf/0.bin` | `e9dea311bb78bba70e6ec5db0196d5c4eba57498b0e8e4321d313025896c8dd0` |
| `manifest.json` | `bac8d289baba16119ba8cf4a82ae1d0a46d47c78b0fff128dc138b35e1dd7643` |

The wheel supports the included public leaf 0. A proof requiring a different leaf needs its authenticated public key material from a separately provisioned runtime. Weights, prover secrets, fitted private model data, tokenizer files and holder proofs are outside the wheel. [Public verifier inputs](../../verifier/proof.py) · [Upstream example provenance](https://github.com/anthropics/FlashProve/tree/9e2bdd8ff5bf9c62f18263d7dac189b0400b260c/examples/maverick#what-is-not-here-and-why)

## Attribution

Built with Llama. The public F4 inputs came from the FlashProve rebuild for Meta's Llama 4 Maverick 17B-128E Instruct, using Unsloth's UD-Q4_K_XL conversion. The upstream example publishes comparison digests. The candidate bundles the measured verification files. The notice records these origins and the terms for the originating model. [Model notice](licenses/Notice) · [Llama 4 Community License](licenses/Llama-4-LICENSE) · [Upstream model provenance](https://github.com/anthropics/FlashProve/blob/9e2bdd8ff5bf9c62f18263d7dac189b0400b260c/THIRD_PARTY.md#what-depends-on-metas-models)

The wheel ships the project license, FlashProve license and notices, BLAKE2 and Plonky2 license texts, and the model attribution. The FlashProve notice also carries the SplitMix64 permission notice. Python dependency wheels install their own license metadata. The clean-install report inventories the versions and license evidence present in that environment. [License inventory](licenses) · [Upstream source credits](https://github.com/anthropics/FlashProve/blob/9e2bdd8ff5bf9c62f18263d7dac189b0400b260c/THIRD_PARTY.md)

The measured native build reproduced the same executable on two Linux hosts. The final wheel installed in a fresh Linux environment and verified a genuine F4 whole-reply proof with network access disabled. The same command returned exit 20 after one proof bit changed. The records identify the wheel, dependency lock and installed public files by digest. [Native build](evidence/native-build.json) · [Clean install and whole-reply check](evidence/native-clean-install.json)
