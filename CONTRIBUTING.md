# Contributing

## Prerequisites

- [circom](https://docs.circom.io/getting-started/installation/) v2.1 or later
- Node.js 18 or later
- [snarkjs](https://github.com/iden3/snarkjs) (installed as a test dependency)

## Repository structure

```
circuits/
  darkdrop.circom          credit note claim circuit (amount private)
  note_pool.circom         note pool claim circuit
  lib/merkle_tree.circom   Poseidon Merkle membership verifier
  test/darkdrop.test.js    proof generation + verification suite
  build/                   local build output, gitignored
```

## Building the circuits

Install the circomlib dependency, then compile each circuit into `circuits/build`:

```bash
cd circuits
npm install

circom darkdrop.circom --r1cs --wasm --sym -o build
circom note_pool.circom --r1cs --wasm --sym -o build/note_pool
```

## Local proving keys

The test suite needs a proving key and a verification key. For development, generate a throwaway Groth16 setup from a small Powers of Tau file. This is **not** a trusted setup and must never be used for a production verifier.

```bash
cd circuits/build
npx snarkjs powersoftau new bn128 14 pot14_0000.ptau
npx snarkjs powersoftau contribute pot14_0000.ptau pot14_0001.ptau --name="dev" -e="dev"
npx snarkjs powersoftau prepare phase2 pot14_0001.ptau pot14_final.ptau

npx snarkjs groth16 setup darkdrop.r1cs pot14_final.ptau darkdrop_v2_0000.zkey
npx snarkjs zkey contribute darkdrop_v2_0000.zkey darkdrop_v2_final.zkey --name="dev" -e="dev"
npx snarkjs zkey export verificationkey darkdrop_v2_final.zkey verification_key_v2.json
```

The test suite expects `build/darkdrop_js/darkdrop.wasm`, `build/darkdrop_v2_final.zkey`, and `build/verification_key_v2.json`. A production deployment will run its own multi-party ceremony for each circuit.

## Running the tests

```bash
cd circuits/test
npm install
node darkdrop.test.js
```

The suite generates and verifies real Groth16 proofs, so each case takes a few seconds. It covers valid claims at several amounts including the one-unit minimum, wrong nullifier, wrong commitment, wrong root, inconsistent recipient halves, zero amount, tampered recipient, and a recipient address above the BN254 field modulus.

## Changing a circuit

Any change to a circuit's constraints or public inputs changes its verification key. When you change a circuit:

1. Recompile and regenerate the local keys as above.
2. Run the test suite.
3. Update ARCHITECTURE.md if the public input set, the leaf format, or a commitment format changed.
4. Call out the change in your pull request description. Verifier implementations key off the public input order.

## Code style

- Keep every public input documented in the circuit header comment.
- Name signals for what they are, not for how a particular chain encodes them.
- Prefer Poseidon for every hash and commitment. Do not introduce a second hash family into the circuits.

## License

By contributing you agree that your contributions will be licensed under the same license as the project, once one is chosen.
