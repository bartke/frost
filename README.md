# Threshold Signatures With Ed25519 - MPC Example

Simple example to show MPC-based distributed key generation and signing using the Edwards 25519 elliptic curve. This is based on the [taurushq-io/frost-ed25519](https://github.com/taurushq-io/frost-ed25519) package and the respective [paper on FROST](https://eprint.iacr.org/2020/852.pdf). FROST eliminates the need for a trusted dealer by using a distributed key generation (DKG) protocol.

This example demonstrates:
1. **Distributed Key Generation (DKG)**: N participants generate a shared public key and individual private key shares without any single party knowing the full private key.
2. **Threshold Signatures**: A (T, N) threshold scheme where any T out of N participants can collaboratively sign a message.
3. **Flexible Round-Optimized Schnorr Threshold Signatures**: Usage of the FROST protocol for key generation and signing.
4. **Ed25519 Signature Verification**: Using the EdDSA signature scheme to verify the collectively generated signature.
5. **Documentation**: Collated explanations of the protocol steps and verification process.

Key Points:
- Private key shares are never combined in a single place.
- Key generation, signing and verification are performed in a distributed manner.
- Public keys and shares are openly shared among participants.
- Multiple rounds of communication are required for both key generation and signing.
- This MPC implementation is secure against up to T-1 malicious participants.
- The example includes verification steps to ensure the integrity of generated keys and signatures.

This single-file example is for educational purposes. For production use, consider a security-audited implementation.

## Background: Elliptic Curves

A finite field is a set of numbers with specific properties and operations (addition and multiplication) that form a closed, associative, commutative, distributive, and invertible algebraic structure. For example, the field  $\mathbb{F}_{2^{255}-19}$ is used in the Edwards25519 curve as its name suggests.

A group is a subset of elements from a finite field where a specific operation (e.g., point addition on an elliptic curve) combines any two elements to form a third element in the group. Groups used in ECC are formed by the points on the elliptic curve with the defined addition operation.

A prime-order subgroup is a subgroup of a larger group where the number of elements (the order) is a prime number. This eliminates small subgroups, preventing easy factorizations and subgroup attacks.

## Background: Signature Verification

Schnorr is a digital signature scheme that can be applied to various elliptic curves and other groups where the discrete logarithm problem is hard. In standard Schnorr signatures, the verification equation is:

$$s \cdot G = R + c \cdot Y$$

Where:
- $s$ is the signature scalar.
- $G$ is the base point of the elliptic curve.
- $R$ is the public nonce.
- $c$ is the challenge, computed as $H(R \| Y \| m)$.
- $Y$ is the public key.

Ed25519 uses a twisted Edwards curve and employs a slightly different verification process for efficiency. The verification equation cofactored is:

$$[8][s]B = [8]R + [8][c]Y$$

Where:
- $[8]$ represents scalar multiplication by 8.
- $s$ is the signature scalar (same as in Schnorr).
- $B$ is the base point of the Edwards curve.
- $R$ is the public nonce  (same as in Schnorr).
- $c$ is the challenge, computed as $H(R \| Y \| m)$ (same as in Schnorr).
- $Y$ is the public key.

Most standard cryptographic libraries and software use the cofactor-less variant for typical Ed25519 key generation, signing, and verification.

### Why Ristretto Points?

The multiplication by 8 accounts for the cofactor in the Edwards curve, the ratio of the order of the elliptic curve group to the order of the largest prime-order subgroup. This means the total group order is 8 times the order of the largest prime-order subgroup.

When generating a key pair with Ed25519 in a single-party context, the private key is a randomly chosen large integer, and the public key is derived by scalar multiplication of the private key with the curve's base point.

In MPC, multiple participants collaboratively generate key shares and compute signatures without ever combining the shares into a single private key. This cofactor can therefore lead subgroup attacks in DKG, as there is a risk that combined operations might inadvertently produce points that lie in smaller subgroups, especially if each participant independently chooses points on the curve.

Ristretto ensures that all points used in the protocol are mapped to the prime-order subgroup.

## Flexible Round-Optimized Schnorr Threshold Signatures

The protocol involves multiple rounds of communication among participants for both the key generation and signing phases. The three steps for key generation are:

### Key Generation
- Parties generate shares of the private key $k$ such that each party $i$ holds a share $k_i$.
- The public key $K$ is computed from these shares without reconstructing the private key.

1. **Initialization**: Each participant (or party) starts with some initial state. The `PartyRoutine(nil, s)` function is called to start this round with no input messages (hence `nil`). Each participant generates some messages to be sent to other participants.
2. **Commit Phase**: Each participant generates their initial secret shares and corresponding commitments. They broadcast these commitments to all other participants.
3. **Share Phase**: Each participant sends their secret shares (encrypted) to all other participants. They receive and verify the shares from others using the commitments received in Round 1.

### Signing

1. **Initialization**: Each participant starts with their share of the secret key and the message to be signed. The `PartyRoutine` initializes the signing process for each participant with no input messages.
2. **Nonce Generation and Sharing**: Each participant generates a random nonce pair (one for the public part and one for the private part) to be used in the signing process.
3. **Partial Signature Generation**: Each participant uses their private key share and the nonces (both their own and the ones received from others) to generate a partial signature on the message.

Participants send their partial signature to a designated combiner (or each other with the peer-to-peer approach). The partial signatures are combined to create the final signature.

**Requirement for $T+1$ Participants**:

In the FROST implementation, the slice of party IDs involved in the signing process must be of length at least $T+1$. This is presumably a requirement from Shamir's Secret Sharing for sufficient shares to reconstruct the group secret.

### Combining Partial Signatures for Schnorr Signatures

1. **Aggregation of Nonces**: The combiner aggregates the public nonces received from all participants. The aggregated nonce $R$ is computed as $R = \sum_{i} R_i$, where $R_i$ are the public nonces from each participant.
2. **Message Hashing**: The combiner hashes the aggregated nonce $R $, the group public key $Y$, and the message $m$ to compute the challenge $c$. The challenge $c$ is computed as $c = H(R \| Y \| m)$, where $H$ is a cryptographic hash function.
3. **Combination of Partial Signatures**: Each participant's partial signature $s_i$ is combined by the combiner to form the final signature. The final signature $s$ is computed as $s = \sum_{i} s_i$.
4. **Verification**: The final signature $s$ is verified by checking that $s \cdot G = R + c \cdot Y$, where $G$ is the base point of the elliptic curve, $R$ is the aggregated nonce, $c$ is the challenge, and $Y$ is the public key.
5. **Output**: The final signature is the pair $(R, s)$, where $R$ is the aggregated nonce and $s$ is the combined partial signature.

## Combining Partial Signatures for Ed25519 using Ristretto encoding

Ed25519 includes a cofactor of 8 in its calculations as seen above. Ristretto encoding maps points on the Edwards25519 curve to a prime-order subgroup, effectively removing the cofactor and the associated small subgroups. Meaning, for Ed25519, this process is slightly different from the traditional Schnorr signatures. Ristretto can be used to encode all the curve points including the public keys, nonces, and the final signature.

1. **Aggregation of Nonces**: The combiner aggregates the public nonces received from all participants. Each nonce is a Ristretto point. The aggregated nonce $R$ is computed as:

$$R = R_1 + R_2 + \ldots + R_n$$

Where $R_i$ are the individual public nonces, and '+' denotes Ristretto point addition.

2. **Challenge Computation**: The combiner computes the challenge $c$ as:

$$c = H(R \| Y \| m)$$

Where:
- $H$ is the hash function, e.g. SHA-512
- $R$ is the encoded aggregated Ristretto point
- $Y$ is the encoded group public key (also a Ristretto point)
- $m$ is the message to be signed

3. **Combination of Partial Signatures**:
Each participant's partial signature $s_i$ (a Ristretto scalar) is combined to form the final signature scalar $s$:

$$s = s_1 + s_2 + \ldots + s_n$$

Where '+' denotes scalar addition in the Ristretto scalar field.

4. **Signature Encoding**: The final signature is the pair $(R, s)$, where:
- $R$ is the encoded aggregated nonce (32 bytes)
- $s$ is the encoded combined signature scalar (32 bytes)

5. **Signature Verification**:
The signature $(R, s)$ is verified by checking:

$$[s]B = R + [c]Y$$

Where:
- $B$ is the Ristretto basepoint
- $[s]B$ and $[c]Y$ denote Ristretto scalar multiplication
- '+' is Ristretto point addition
- All points are in their Ristretto-encoded form

The verification equation doesn't include the cofactor of 8 explicitly, as the Ristretto encoding handles the cofactor internally.

### Messages and complexity
- Each participant sends messages to all other participants in the first round, leading to a total of N * (N - 1) messages (where N is the number of participants).
- For the second round, it is reduced due to the specific protocol requirements, leading to N * (N - 1) / 2 messages, reflecting a point-to-point communication pattern.

## Secret Shares vs. Full Key

There are secret shares generated by each participant during the key generation phase. Each participant ends up with a share of the overall secret key (not the full key itself). These shares are necessary for the threshold-based signing.

A partial leak doesn't compromise the validity of the signature scheme, it does however undermine its security. The key is compromised if enough shares leak to meet or exceed the threshold T.

### Public Information

All participants must agree on the same group public key. This is the collective public key representing the entire group.

Further, each participant should have the same set of public shares, which includes:
- The group public key
- Public key shares for all participants
- The set of participant IDs

This enables for all participants to verify partial signatures from others during the signing process. The group presents a unified identity to external verifiers. Signing operations can be performed correctly by any subset of participants meeting the threshold.

### Lagrange Interpolation for Secret Sharing

Participants verify that their secret shares combine correctly to form the expected group public key by using Lagrange interpolation. The core idea is based on the fact that a polynomial of degree T-1 is uniquely determined by T points on that polynomial.

Public Key Verification:
- Each share $k_i$ corresponds to a partial public key $K_i = g^{k_i} $, where $g$ is the generator of the elliptic curve group.

To verify the distributed key generation, we use Lagrange interpolation to combine the public key shares and check that they match the expected group public key $K$.

Verification Process:
- **Lagrange Coefficients:** Calculate the coefficients $\lambda_i$ for combining the public key shares.
- **Combine Public Key Shares:** Use the Lagrange coefficients to combine the public key shares $K_i$:

$$K = \prod_{i=1}^{t} K_i^{\lambda_i}$$

- **Match Expected Public Key:** Compare the combined public key $K$ to the expected group public key $G$. If they match, the distributed key shares are verified to be correct.

These principle remains the same for Schnorr and Ristretto points and encoding.
- Operations would be in the Ristretto prime-order group, implicitly handling the cofactor.
- Point multiplication would be represented as scalar multiplication of Ristretto points.
- The product operation would be replaced with a sum of Ristretto points.

Public Key Verification:
- Each share $k_i$ corresponds to a partial public key $A_i = [k_i]B$, where $B$ is the basepoint of the Edwards25519 curve.

To verify the distributed key generation, we use Lagrange interpolation to combine the public key shares and check that they match the expected group public key $A$.

Verification Process:
1. **Lagrange Coefficients**: Calculate the coefficients $\lambda_i$ for combining the public key shares.

2. **Combine Public Key Shares**: Use the Lagrange coefficients to combine the public key shares $A_i$:

$$A_{\text{combined}} = \sum_{i=1}^{t} \lambda_i \cdot A_i$$

For the Edwards curve context, use point addition instead of multiplication.

3. **Match Expected Public Key**: Compare the combined public key $A_{\text{combined}}$ to the expected group public key $A$. If they match, the distributed key shares are verified to be correct.

The verification is successful if:

$$A_{\text{combined}} = A$$
