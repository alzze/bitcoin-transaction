#!.venv/bin/python3

import random, hashlib, ecdsa, bech32
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


def generate_public_key(privkey: bytes) -> bytes:
  # K = k × G
  k = int.from_bytes(privkey, 'big')
  K = ecdsa.SECP256k1.generator * k
  prefix = b'\x02' if K.y() % 2 == 0 else b'\x03'

  return prefix + K.x().to_bytes(32, 'big')

def generate_p2wpkh(pubkey: bytes) -> str:
  sha = hashlib.sha256(pubkey).digest()
  h160   = hashlib.new("ripemd160", sha).digest()
  hrp = 'tb'

  prog   = bech32.convertbits(h160, 8, 5)       # bech32 alphabet, 32 = 2⁵
  address   = bech32.bech32_encode(hrp, [0] + prog) 

  return address

if __name__ == "__main__":
  private_key1 = import_private_key(".private_key1")
  private_key2 = import_private_key(".private_key2")

  address_1 = generate_p2wpkh(generate_public_key(private_key1))
  address_2 = generate_p2wpkh(generate_public_key(private_key2))

  print(address_1, address_2)