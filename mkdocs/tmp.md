To encrypt or sign a full message, we must convert it into an integer before applying RSA.

```python
def text_to_int():
    pass

def int_to_text():
    pass
```

RSA cannot encrypt large messages directly because `m` must be smaller than `n`.  To handle a large text, we split it into chunks that fit within `n`

```python
def chunk_message()
    pass

def unchunk_message():
    pass
```

Here’s how to encrypt and decrypt long messages using chunking in RSA!
- Split the message into small chunks that fit within `n`
- Each chunk is converted to int and encrypted separately using public key
- Upon receiving, each chunk is decrypted using private key and, then, joined to reconstruct the message

```python
def cifrar(self, mensagem: str = None) -> Optional[list[int]]:
    pass

def decifrar(self, mensagem_cifrada: list[int]) -> Optional[str]:
    pass
```

Why Do We Need Padding in RSA?

RSA encryption is deterministic—encrypting the same message twice gives the same ciphertext. This makes it vulnerable to attacks (e.g., dictionary attacks, where an attacker precomputes encrypted values for common messages).

Padding adds randomness, making RSA more secure.

Simple Padding Scheme
To make RSA more secure without external libraries, we can use a simple padding scheme:

- Before encryption, we add random bytes to the message.
- After decryption, we remove the padding.

```python
import os

def add_padding(message: str, block_size: int) -> bytes:
    """Adds random padding to a message before encryption."""
    msg_bytes = message.encode()
    padding_length = block_size - len(msg_bytes) - 1  # -1 for a separator
    if padding_length < 0:
        raise ValueError("Message too long for this block size")
    padding = os.urandom(padding_length)  # Generate random padding
    return padding + b'\x00' + msg_bytes  # Add a separator (null byte)

def remove_padding(padded_message: bytes) -> str:
    """Removes padding after decryption."""
    return padded_message.split(b'\x00', 1)[1].decode()  # Extract original message
```

Why Padding Helps
- Randomness: Each encryption produces different ciphertext (even for the same message).
- Prevents Attacks: No attacker can precompute a dictionary of possible encrypted values.
- Preserves Original Message: The padding is safely removed after decryption.

Let's integrate padding into chunked encryption so that each chunk has random padding before encryption and the padding is removed after decryption.
