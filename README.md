# PMSE
Pretty Modular Symetric Encryption (PMSE) - C version

Web demo of PMSE:  http://blocksnet.free.fr/PMSE/

Web demo of PULS (PRNG of PMSE): http://blocksnet.free.fr/PRNG/

Preprint: https://doi.org/10.48550/arXiv.1905.08150

Fast C version:  https://github.com/elunaire/PMSE/tree/C-version


PMSE (Pretty Modular Symetric Encryption) use 1 or 2 passwords in order to create a pseudo-random key as long as the message to be encrypted, including data deconstruction and reconstruction. Encryption method tested with image encryption tends to the entropy obtained with One-Time-Pad encryption (cf. https://doi.org/10.48550/arXiv.1905.08150 ). The C version (cf. C-branch) is pretty fast and well suited for 8-bits microcontrollers.

