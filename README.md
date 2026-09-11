# PQ-ThPlA
Post-Quantum Threshold Password Less Authentication


for ML-KEM library selection:
  - libcrux by Cryspen


 why ?

 the existing python library requires around 0.5 - 1.1 ms (micro-second) in time to complete one round of encacpsulation and decapsulation . 
 It is based on a rust library (cryptography.io)  ,

 -> why not cryptogrraphy.io ?

 the cryptography.io ml-kem is not audited means less security and is comparably slower to libcrux and even libcrux is faster than cryptography.io , optimized through APX2 and NEON , so the choice for ML-KEM is libcrux .

 also libcrux provide personalization for key length selection and inputs for key-generation and shared secret genration
 
