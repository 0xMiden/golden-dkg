# Trust registry admission for identity-key knowledge

For this refactor, assume that the authenticated deployment process admitting a participant to the registry has established that the participant knows the secret for its Golden identity public key. `golden-core` continues to validate canonical, nonidentity, unique keys and bind dealer proofs to the registered key, but it does not carry or verify a separate identity-key proof of knowledge. A future protocol version may require proof-bearing identity keys without anticipating that interface now.
