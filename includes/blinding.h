#include "gmp.h"

/* m' = (m * r^e) mod n avec r random entre 0 et n inversible mod */
void blinding_message(gmp_randstate_t state, mpz_t m, const mpz_t e, const mpz_t n, mpz_t r_inv);

// démasquer : s = s' * r^{-1} mod n = m^d mod n car s' = (m')^d mod n = m^d * r mod n
void unblinding_message(mpz_t s, mpz_t r_inv, const mpz_t n);

/* N' = rN, r de 128bits, ne modifie pas l'entrée N, modifie N' */
void blinding_modulus(const mpz_t N, mpz_t N_prime, gmp_randstate_t randstate);

/* d' = d + k phi(n) et s = m^d mod n = m^d' mod n par Euler, pas besoin d'unmask */
void blinding_exponent(gmp_randstate_t state, mpz_t d, const mpz_t phi_n);

int test_blinding(gmp_randstate_t state);
