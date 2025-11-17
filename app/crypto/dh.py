"""
Diffie-Hellman key exchange and key derivation
"""
import os
from app.common.utils import sha256_digest, int_to_bytes_bigendian


# 2048-bit safe prime (RFC 3526 Group 14)
DEFAULT_DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)

DEFAULT_DH_GENERATOR = 2


class DHKeyExchange:
    """Handles Diffie-Hellman key exchange"""
    
    def __init__(self, p: int = None, g: int = None):
        """
        Initialize DH parameters
        p: prime modulus
        g: generator
        """
        self.p = p or DEFAULT_DH_PRIME
        self.g = g or DEFAULT_DH_GENERATOR
        self.private_key = None
        self.public_key = None
        
    def generate_keypair(self) -> int:
        """
        Generate private key and compute public key
        Returns: public key (A or B)
        """
        # Generate random private key (a or b)
        key_size = (self.p.bit_length() + 7) // 8
        self.private_key = int.from_bytes(os.urandom(key_size), 'big') % (self.p - 2) + 1
        
        # Compute public key: g^a mod p or g^b mod p
        self.public_key = pow(self.g, self.private_key, self.p)
        
        return self.public_key
    
    def compute_shared_secret(self, peer_public_key: int) -> int:
        """
        Compute shared secret from peer's public key
        peer_public_key: A (if we're server) or B (if we're client)
        Returns: shared secret Ks = peer_public^private mod p
        """
        if self.private_key is None:
            raise ValueError("Must generate keypair first")
        
        # Compute Ks = B^a mod p = A^b mod p
        shared_secret = pow(peer_public_key, self.private_key, self.p)
        return shared_secret
    
    def derive_aes_key(self, shared_secret: int) -> bytes:
        """
        Derive AES-128 key from shared secret
        K = Truncate_16(SHA256(big_endian(Ks)))
        """
        # Convert shared secret to big-endian bytes
        ks_bytes = int_to_bytes_bigendian(shared_secret)
        
        # Hash with SHA-256
        hash_digest = sha256_digest(ks_bytes)
        
        # Truncate to 16 bytes for AES-128
        aes_key = hash_digest[:16]
        
        return aes_key


def perform_dh_exchange_client(p: int = None, g: int = None) -> tuple[DHKeyExchange, int]:
    """
    Client side: generate parameters and keypair
    Returns: (dh_instance, public_key_A)
    """
    dh = DHKeyExchange(p, g)
    public_A = dh.generate_keypair()
    return dh, public_A


def perform_dh_exchange_server(p: int, g: int, client_public_A: int) -> tuple[bytes, int]:
    """
    Server side: receive client params, generate keypair, compute key
    Returns: (aes_key, public_key_B)
    """
    dh = DHKeyExchange(p, g)
    public_B = dh.generate_keypair()
    
    # Compute shared secret and derive AES key
    shared_secret = dh.compute_shared_secret(client_public_A)
    aes_key = dh.derive_aes_key(shared_secret)
    
    return aes_key, public_B


def finalize_dh_exchange_client(dh: DHKeyExchange, server_public_B: int) -> bytes:
    """
    Client side: receive server public key and compute final AES key
    Returns: aes_key
    """
    shared_secret = dh.compute_shared_secret(server_public_B)
    aes_key = dh.derive_aes_key(shared_secret)
    return aes_key
