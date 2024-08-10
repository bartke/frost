# FROST MPC - Threshold Signatures With Ed25519

Example to show MPC-based distributed key generation and signing using the Edwards 25519 elliptic curve. This example is based on the [taurushq-io/frost-ed25519](https://github.com/taurushq-io/frost-ed25519) package and the respective [paper on FROST](https://eprint.iacr.org/2020/852.pdf) to show message exchange via JSON. FROST eliminates the need for a trusted dealer by using a distributed key generation (DKG) protocol.

This example demonstrates:
1. **Distributed Key Generation (DKG)**: N participants generate a shared public key and individual private key shares without any single party knowing the full private key.
2. **Threshold Signatures**: A (T, N) threshold scheme where any T out of N participants can collaboratively sign a message.
3. **Flexible Round-Optimized Schnorr Threshold Signatures**: Usage of the FROST protocol for key generation and signing.
4. **Ed25519 Signature Verification**: Using the EdDSA signature scheme to verify the collectively generated signature.
5. **Documentation**: Collated explanations of the protocol steps and verification process.

Key Points:
- Private key shares are never combined in a single place.
- Key generation, signing and verification performed in a distributed manner.
- Two rounds of communication are required for both key generation and signing.
- This MPC implementation is secure against up to T-1 malicious participants.
- The example includes verification steps to ensure the integrity of generated keys and signatures.

## Usage

These single-file examples for keygen and signing is for educational purposes only.

```go
import "github.com/bartke/frost"
```

See [cmd/keygen](cmd/keygen/main.go) and [cmd/sign](cmd/sign/main.go) for example usage. This is demonstrated in the Makefile:

```sh
# Generates N=5, T=2 key shares via JSON file exchange.
make keygen
# Signs this README.md using the generated key shares with T+1 participants.
make sign
# Verify the signature independently with the ed25519 standard library package.
go run ./cmd/verify <pubkey> <signature> ./README.md
Signature is valid.
```

## Dependencies

The package has a minimal set of third-party dependencies, mainly Filippo Valsorda's [filippo.io/edwards25519](https://github.com/FiloSottile/edwards25519) for lower level operations on the Edwards25519 curve that are not provided by the `crypto/ed25519` standard library package.

## Acknowledgment

This codebase is heavily based on the work from [TaurusHQ's FROST Ed25519 implementation](https://github.com/taurushq-io/frost-ed25519), which is licensed under the Apache-2.0 license. Significant modifications have been made to adapt the original code to demonstrate simple JSON message exchange.

## Background and Discussion

### Elliptic Curves

A finite field is a set of numbers with specific properties and operations (addition and multiplication) that form a closed, associative, commutative, distributive, and invertible algebraic structure. For example, the field  $\mathbb{F}_{2^{255}-19}$ is used in the Edwards25519 curve, as its name suggests.

A group is a subset of elements from a finite field where a specific operation (e.g., point addition on an elliptic curve) combines any two elements to form a third element in the group. Groups used in ECC are formed by the points on the elliptic curve with the defined addition operation.

A prime-order subgroup is a subgroup of a larger group where the number of elements (the order) is a prime number. This eliminates small subgroups, preventing easy factorizations and subgroup attacks.

### Signature Verification

Schnorr is a signature scheme that can be applied to various elliptic curves and other groups where the discrete logarithm problem is hard. It involves generating a nonce, creating a commitment from that nonce, and then producing a signature using the private key and the commitment. In standard Schnorr signatures, the verification equation is:

$$s \cdot G = R + c \cdot Y$$

Where:
- $s$ is the signature scalar.
- $G$ is the base point of the elliptic curve.
- $R$ is the public nonce.
- $c$ is the challenge, computed as $H(R \| Y \| m)$.
- $Y$ is the public key.

Ed25519 uses a twisted Edwards curve and employs a slightly different verification process. The cofactored verification equation is:

$$[8][s]B = [8]R + [8][c]Y$$

Where:
- $[8]$ represents scalar multiplication by 8.
- $s$ is the signature scalar (same as in Schnorr).
- $B$ is the base point of the Edwards curve.
- $R$ is the public nonce  (same as in Schnorr).
- $c$ is the challenge, computed as $H(R \| Y \| m)$ (same as in Schnorr).
- $Y$ is the public key.

The multiplication by 8 accounts for the cofactor in the Edwards curve, the ratio of the order of the elliptic curve group to the order of the largest prime-order subgroup. This means the total group order is 8 times the order of the largest prime-order subgroup and there are 8 equivalent points on the curve for any given point

Most standard cryptographic libraries and software use the cofactor-less variant for typical Ed25519 key generation, signing, and verification. When using the cofactored version of Ed25519, operations like point multiplication and signature generation must account for the curve’s cofactor.

In FROST MPC, the partial signature scalar $s_i$ is generated in SignRound1 and verified against the group public key in SignRound2.

### Why Ristretto Points?

When generating a key pair with Ed25519 in a single-party context, the private key is a randomly chosen large integer, and the public key is derived by scalar multiplication of the private key with the curve's base point.

In MPC, multiple participants collaboratively generate key shares and compute signatures without ever combining the shares into a single private key. This cofactor can therefore lead subgroup attacks in DKG, as there is a risk that combined operations might inadvertently produce points that lie in smaller subgroups, especially if each participant independently chooses points on the curve.

[Ristretto](https://ristretto.group/) ensures that all points used in the protocol are mapped to the prime-order subgroup.

## Flexible Round-Optimized Schnorr Threshold Signatures

The protocol involves multiple rounds of communication among participants for both the key generation and signing phases. The three steps for key generation are:

### Key Generation
- Parties generate shares of the private key $k$ such that each party $i$ holds a share $k_i$.
- The public key $K$ is computed from these shares without reconstructing the private key.

1. **Initialization**: Each participant generates a secret and a corresponding polynomial. The polynomial’s constant term is the secret, and the degree is $T-1$, where $T$ is the threshold for reconstructing the key.
2. **Commitments Phase**: Each participant computes and securely shares key shares with others, using the commitments to verify correctness. Verified shares are then used to compute partial public keys.
3. **Share Phase**: Each participant sends their secret shares (encrypted) to all other participants. The group public key is reconstructed using Lagrange Interpolation from the participants' public key shares.

Key points:
- The private key is never fully reconstructed.
- The protocol is secure as long as fewer than T participants are compromised.
- All participants must agree on the final public key.

### Signing

1. **Initialization**: Each participant prepares by loading their secret key share and the message to be signed. Participants generate random nonces ($D_i$ and $E_i$) and send commitments to these nonces to all other participants.
2. **Nonce Generation and Partial Signature Computation**: Participants compute a shared nonce ($R$) by combining all received nonce commitments. They compute a challenge ($c$) based on the aggregated nonce, the group public key, and the message. Each participant computes their partial signature using their Lagrange-weighted secret key share, the challenge, and their nonce. These partial signatures are sent to any party who acts as the designated combiner.
3. **Signature Combination**: Any party can aggregate the partial signatures from $T$ other parties to form the final signature `(R, s)`. The final signature is verified to ensure its validity against the group public key.

Key points:
- The full private key is never reconstructed during signing.
- A minimum of $T+1$ participants is required to generate a valid signature, $T$ plus the combiner.
- The final signature can be verified using standard Ed25519 verification methods.

**Requirement for $T+1$ Signers**:

The Threshold T defines the maximum number of parties that may be corrupted. I.e. if we have N=5 and T=2, we require at least 3 participants to sign. In other words, we require T+1 participants to sign a message.

### Combining Partial Signatures for Schnorr Signatures

1. **Aggregation of Nonces**: Any party can be a combiner, to do so, it aggregates the public nonces received from all participants. The aggregated nonce $R$ is computed as $R = \sum_{i} R_i$, where $R_i$ are the public nonces from each participant.
2. **Message Hashing**: The combiner hashes the aggregated nonce $R $, the group public key $Y$, and the message $m$ to compute the challenge $c$. The challenge $c$ is computed as $c = H(R \| Y \| m)$, where $H$ is a cryptographic hash function.
3. **Combination of Partial Signatures**: Each participant's partial signature $s_i$ is combined by the combiner to form the final signature. The final signature $s$ is computed as $s = \sum_{i} s_i$.
4. **Verification**: The final signature $s$ is verified by checking that $s \cdot G = R + c \cdot Y$, where $G$ is the base point of the elliptic curve, $R$ is the aggregated nonce, $c$ is the challenge, and $Y$ is the public key.
5. **Output**: The final signature is the pair $(R, s)$, where $R$ is the aggregated nonce and $s$ is the combined partial signature.

## Combining Partial Signatures for Ed25519 using Ristretto encoding

Ed25519 includes a cofactor of 8 in its calculations as seen above. Ristretto encoding maps points on the Edwards25519 curve to a prime-order subgroup, effectively removing the cofactor and the associated small subgroups. The protocol for combining partial signatures is similar to the Schnorr case, with the following steps:

- **Nonce Aggregation**: The party that combines signatures, aggregates public nonces $R_i$ from $T$ participants. The combined nonce $R$ is calculated as $R = \sum R_i$.
- **Challenge Calculation**: The combiner computes the challenge $c = H(R \| Y \| m)$, where $Y$ is the group public key and $m$ is the message.
- **Partial Signature Combination**: Each participant’s partial signature $s_i$ is aggregated: $s = \sum s_i$. The final signature is $(R, s)$, where $R$ is the aggregated nonce and $s$ is the combined scalar.
- **Verification**: Verify the signature using $[s]B = R + [c]Y$, with all points and operations in the Ristretto encoding.

Using Ristretto ensures the signature operates within the prime-order subgroup, mitigating small subgroup vulnerabilities inherent in Ed25519.

### Messages and complexity

- Each participant sends messages to all other participants in the first round, leading to a total of $N \times (N - 1)$ messages (where $N$ is the number of participants).
- For the second round, it is reduced due to the specific protocol requirements, leading to $N \times (N - 1) / 2$ messages, i.e. point-to-point communication.

## Secret Shares vs. Full Key

There are secret shares generated by each participant during the key generation phase. Each participant ends up with a share of the overall secret key (not the full key itself). These shares are necessary for the threshold-based signing.

A partial leak doesn't compromise the validity of the signature scheme, it does however undermine its security. The key is compromised if enough shares leak to meet or exceed the threshold $T$.

### Public Information

All participants must agree on the same group public key. This is the collective public key representing the entire group.

Further, each participant should have the same set of public shares, which includes:
- The group public key
- Public key shares for all participants
- The set of participant IDs

This enables for all participants to verify partial signatures from others during the signing process. The group presents a unified identity to external verifiers. Signing operations can be performed correctly by any subset of participants meeting the threshold.

### Lagrange Interpolation for Secret Sharing

Lagrange Interpolation is used to reconstruct a polynomial from a given set of points. Participants verify that their secret shares combine correctly to form the expected group public key by using Lagrange interpolation. A polynomial of degree T-1 is uniquely determined by T points on that polynomial, i.e. the secret can be reconstructed only when a threshold number of shares are combined.

It is used in SignRound0 to compute weighted public key shares and normalize the secret key share. In SignRound2, the verification ensures the reconstructed public key matches the expected value.

- **Calculate Lagrange Coefficients**: Compute coefficients $\lambda_i$ for each participant, which weight their contributions to the combined public key.
- **Combine Public Key Shares**: Each participant's public key share $A_i$ (a Ristretto point) is multiplied by its corresponding coefficient. The group public key $A$ is reconstructed by summing these weighted shares: $A = \sum \lambda_i \cdot A_i$.
- **Verification**: The reconstructed group public key $A$ is compared to the expected group public key to ensure consistency.

The operations are performed in the Ristretto prime-order group, implicitly handling the cofactor.
