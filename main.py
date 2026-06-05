#!.venv/bin/python3

import random, hashlib
from base58 import b58encode, b58decode_check

def base58check(payload:bytes) -> str:
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58encode(payload + checksum).decode("utf-8")

def private_key_generator():
  # stored in .private_key1 and .private_key2 files
    secp256k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    priv_key = random.randint(1, secp256k1_order - 1).to_bytes(32,"big")

    testnet_prefix = bytes([0xEF])
    WIF_compressed_suffix = bytes([0x01])

    return base58check(testnet_prefix + priv_key + wif_compressed_suffix)

def import_private_key(file:str) -> bytes:
  WIF = open(file).read()
  decoded = b58decode_check(WIF)

  prefix = decoded[:1] 
  private_key = decoded[1:-1]
  suffix = decoded[-1:] 
  testnet_network = True if prefix == bytes([0xEF]) else False
  WIF_compressed = True if suffix == bytes([0x01]) else False

  if not testnet_network:
    raise ValueError("Only testnet WIFs are supported")

  if not WIF_compressed:
    raise ValueError("Compressed WIF required")

  return private_key 

if __name__ == "__main__":
  private_key1 = import_private_key(".private_key1")
  private_key2 = import_private_key(".private_key2")
