# Sealed pickup reference vector

Run `make test-pickup-crypto` to check [pickup-v1.json](pickup-v1.json).
The fixture contains public test credentials and a fixed nonce. Its correctly
authenticated envelope and its wrong-AAD counterpart use the same sample
plaintext, nonce and key. Their final 16-byte tags differ by construction.
The protocol requires a fresh random nonce for sealing. [RFC-0010](../../docs/rfcs/RFC-0010-router-pickup.md#proposed-design)

## Encoding and encryption

The vector was generated with Node.js 24.22.1, `canonicalize@2.1.0`,
`node:crypto` and `@noble/ciphers@1.3.0`. It records the byte-length-framed
hash preimage, both hashes, the derived encryption key, associated data,
canonical plaintext and wire envelope as lowercase hex. The original message
array retains its text parts. Its Unicode includes U+00E9 and U+0065 U+0301
to expose accidental normalization. [Canonical JSON](https://www.rfc-editor.org/rfc/rfc8785)

To reproduce the ciphertext, hash `k_preimage_hex` as raw bytes with SHA-256.
Pass that digest as the input key material to HKDF-SHA256, with absent salt,
UTF-8 info `enc` and output length 32. Encrypt the bytes of
`verification_jcs_hex` with `xchacha20poly1305(key, nonce, aad).encrypt(plaintext)`.
The associated data consists of UTF-8 `akashi-pickup/1` followed by the 32 raw
pickup ID bytes. Flipping the last bit of that ID produces `wrong_aad_hex`.
Python RFC 8785, HMAC-SHA256 and PyNaCl/libsodium independently reproduced
the intermediate values, opened each ciphertext with its own AAD and rejected
the wrong-AAD ciphertext under the protocol AAD. [HKDF](https://www.rfc-editor.org/rfc/rfc5869) · [XChaCha20-Poly1305](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03)

## Signed verification payload

The prompt IDs were produced by Transformers 5.17.0 using the tokenizer files
at F37's pinned revision. The reference joined text parts for rendering,
applied the packaged template with the generation prompt, fixed date
`26 Jul 2024` and absent tools, then encoded without adding special tokens.
The synthetic reply fills its 13-token budget and decodes to the exact Unicode
reply text. The independent gateway renderer reproduced the prompt IDs and
reply text. [Renderer revision](https://github.com/Lucid-Computing/akashi/blob/514aedc0e0ee001e6c2131c4cee768441ba8ad27/gateway/renderer.py) · [Rendering contract](../../docs/rfcs/RFC-0002-canonical-rendering.md)

Node.js encoded the receipt using the v1 framed transcript and public-leaf
preimages, then signed `PromiseReceipt || log_id || leaf_hash` with Ed25519.
The seed is public test 1 from RFC 8032 section 7.1. The fixed log identity
and public key match the receipt test vectors. The receipt verifier recomputed
the committed budget, tokens and leaf, then checked the signature against that
public key. [Data model](../../docs/spec/03-data-model.md#binding-invariants) · [Receipt verifier revision](https://github.com/Lucid-Computing/akashi/blob/9eec6103f4d909f6c891f66a42fab629f5f6bd74/log/receipt.py) · [Ed25519 test seed](https://www.rfc-editor.org/rfc/rfc8032#section-7.1)
