def compute_encid(my_private_key, peer_public_key_bytes):

    peer_public_key = X25519PublicKey.from_public_bytes(peer_public_key_bytes)

    shared_key = my_private_key.exchange(peer_public_key)

    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared_key)
    return digest.finalize()
