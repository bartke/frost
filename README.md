# Ed25519 MPC Example

Simple example to show MPC-based distributed key generation and signing using the Edwards 25519 elliptic curve. This involves multiple rounds of communication among participants to generate a shared public/private key pair and then use that pair to sign a message. The process includes several validation steps to ensure the integrity and correctness of the generated keys and signatures. This is based on the [taurushq-io/frost-ed25519](https://github.com/taurushq-io/frost-ed25519) package and [paper](https://eprint.iacr.org/2020/852.pdf).

Threshold (T) and Number of Participants (N):
- **N**: Total number of participants.
- **T**: Threshold number of participants required to successfully complete the protocol. For example, T out of N means that at least T participants are needed to generate a valid key or signature. FROST is secure against up to T-1 malicious participants.
