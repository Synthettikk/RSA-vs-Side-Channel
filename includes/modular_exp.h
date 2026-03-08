/* Quelques fonctions classiques simples d'exponentiation modulaire sur grands entiers 
Attention : on utilise GMP pour les opérations sur grands entiers, qui n'est pas constant time ! 
Chaque fonction prend en entrée 4 mpz_t : result, m, d et n 
calcule m^d mod n et met le résultat dans result */

#include "gmp.h"


// NON REGULAR


/* non regular modular exp, cost : 1 Square + 0.5 Mult per exponent bit
vulnerable to SPA */
void square_and_muliply_left_to_right(mpz_t result, const mpz_t m, const mpz_t d, const mpz_t n);

/* non regular modular exp, cost : 1 Square + 0.5 Mult per exponent bit
vulnerable to SPA */
void square_and_muliply_right_to_left(mpz_t result, const mpz_t m, const mpz_t d, const mpz_t n);


// REGULAR


/* regular modular exp, cost : 1 Square + 1 Mult per exponent bit
vulnerable to safe error analysis */
void square_and_muliply_always_left_to_right(mpz_t result, const mpz_t m, const mpz_t d, const mpz_t n);

/* regular modular exp, cost : 1 Square + 1 Mult per exponent bit
a, b and c (or R0, R1, R2) always verify : c = (a × b × m) mod n.
This can be used as a consistency check to prevent safe error analysis */
void square_and_muliply_always_right_to_left(mpz_t result, const mpz_t m, const mpz_t d, const mpz_t n);

/* regular modular exp, cost : 1 Square + 1 Mult per exponent bit
left-to-right, safe.
without detection of faults attacks */
void Montgomery_ladder(mpz_t result, const mpz_t m, const mpz_t d, const mpz_t n);

/* regular modular exp, cost : 1 Square + 1 Mult per exponent bit
left-to-right, safe.
R1 == R0 × m mod n allows detection of faults attacks */
void Montgomery_ladder_fault(mpz_t result, const mpz_t m, const mpz_t d, const mpz_t n);

/* regular modular exp, cost : 1 Square + 1 Mult per exponent bit
right-to-left counterpart of the Montgomery ladder.
without detection of faults attacks */
void Joye_ladder(mpz_t result, const mpz_t m, const mpz_t d, const mpz_t n);



/* tests for modular exp methods */
int test_exp();
