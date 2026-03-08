/* Quelques fonctions classiques simples d'exponentiation modulaire sur grands entiers 
Attention : on utilise GMP pour les opérations sur grands entiers, qui n'est pas constant time ! 
Chaque fonction prend en entrée 4 mpz_t : result, m, d et n 
calcule m^d mod n et met le résultat dans result */

#include <sys/types.h>
#include "../includes/modular_exp.h"
#include <stdio.h>

/* r <- a x b mod n */
static inline void mpz_mul_mod(mpz_t r, const mpz_t a, const mpz_t b, const mpz_t m){
    mpz_mul(r, a, b);
    mpz_mod(r, r, m);
}


// NON REGULAR


/* non regular modular exp, cost : 1 Square + 0.5 Mult per exponent bit
vulnerable to SPA */
void square_and_muliply_left_to_right(mpz_t result, const mpz_t m, const mpz_t d, const mpz_t n){
    mpz_t base;
    mpz_init(base);

    /* result <- 1 */
    mpz_set_ui(result, 1);

    /* copy base = m mod n (ensure 0 <= base < n) */
    mpz_mod(base, m, n);

    /* find number of bits in exponent d */
    size_t nbits = mpz_sizeinbase(d, 2);
    if (nbits == 0) { /* exponent == 0 */
        mpz_set_ui(result, 1);
        mpz_clear(base);
        return;
    }

    /* process bits from most-significant to least-significant (left-to-right) */
    for (ssize_t i = nbits - 1; i >= 0; --i) {
        /* result = (result * result) mod n  -- square */
        mpz_mul_mod(result, result, result, n);

        /* if bit i of d is 1, result = (result * base) mod n -- multiply */
        if (mpz_tstbit(d, i)) {
            mpz_mul_mod(result, result, base, n);
        }
    }

    mpz_clear(base);
}

/* non regular modular exp, cost : 1 Square + 0.5 Mult per exponent bit
vulnerable to SPA */
void square_and_muliply_right_to_left(mpz_t result, const mpz_t m, const mpz_t d, const mpz_t n){
    mpz_t base;
    mpz_init(base);

    /* result <- 1 */
    mpz_set_ui(result, 1);

    /* copy base = m mod n (ensure 0 <= base < n) */
    mpz_mod(base, m, n);

    /* find number of bits in exponent d */
    size_t nbits = mpz_sizeinbase(d, 2);
    if (nbits == 0) { /* exponent == 0 */
        mpz_set_ui(result, 1);
        mpz_clear(base);
        return;
    }

    /* process bits from least-significant to most-significant (right-to-left) */
    for(unsigned long int i = 0; i < nbits; i++){
        /* if bit i of d is 1, result = (result * base) mod n -- multiply */
        if(mpz_tstbit(d, i)){
            mpz_mul_mod(result, result, base, n);
        }
        /* base = (base * base) mod n  -- square */
        mpz_mul_mod(base, base, base, n);
    }
    
    mpz_clear(base);
}


// REGULAR


/* regular modular exp, cost : 1 Square + 1 Mult per exponent bit
vulnerable to safe error analysis */
void square_and_muliply_always_left_to_right(mpz_t result, const mpz_t m, const mpz_t d, const mpz_t n){
    mpz_t R[2], base;
    mpz_inits(R[0], R[1], base, NULL);

    /* R[0] <- 1 */
    mpz_set_ui(R[0], 1);

    /* copy base = m mod n (ensure 0 <= base < n) */
    mpz_mod(base, m, n);

    /* find number of bits in exponent d */
    size_t nbits = mpz_sizeinbase(d, 2);
    if (nbits == 0) { /* exponent == 0 */
        mpz_set_ui(result, 1);
        mpz_clears(R[0], R[1], base, NULL);
        return;
    }

    /* process bits from most-significant to least-significant (left-to-right) */
    for (ssize_t i = nbits - 1; i >= 0; --i) {
        /* R0 <- R0 x R0 % n (square) */
        mpz_mul_mod(R[0], R[0], R[0], n);
        /* R[1 - d_i] <- R0 x m % n (mult) va dans R[0] ssi d_i == 1 */
        mpz_mul_mod(R[1 - mpz_tstbit(d, i)], R[0], base, n); 
    }
    mpz_set(result, R[0]);

    /* clear memory */
    mpz_clears(R[0], R[1], base, NULL);
}

/* regular modular exp, cost : 1 Square + 1 Mult per exponent bit
a, b and c (or R0, R1, R2) always verify : c = (a × b × m) mod n.
This can be used as a consistency check to prevent safe error analysis */
void square_and_muliply_always_right_to_left(mpz_t result, const mpz_t m, const mpz_t d, const mpz_t n){
    mpz_t R[3], base, c;
    mpz_inits(R[0], R[1], R[2], base, c, NULL);

    /* copy base = m mod n (ensure 0 <= base < n) */
    mpz_mod(base, m, n);
    
    /* R[0] <- 1 */
    mpz_set_ui(R[0], 1);
    /* R[1] <- 1 */
    mpz_set_ui(R[1], 1);
    /* R[2] <- m */
    mpz_set(R[2], base);

    /* find number of bits in exponent d */
    size_t nbits = mpz_sizeinbase(d, 2);
    if (nbits == 0) { /* exponent == 0 */
        mpz_set_ui(result, 1);
        mpz_clears(R[0], R[1], R[2], base, c, NULL);
        return;
    }

    /* process bits from leasr-significant to most-significant (right-to-left) */
    for (size_t i = 0; i < nbits; i++) {
        /* R1−di <- R1−di × R2 mod n */
        mpz_mul_mod(R[1 - mpz_tstbit(d, i)], R[1 - mpz_tstbit(d, i)], R[2], n); 
        /* R2 <- R2 ^ 2*/
        mpz_mul_mod(R[2], R[2], R[2], n); 

        /* safe error analysis prevent */
        /* c = R0 x R1 x m mod n */
        mpz_mul_mod(c, R[0], R[1], n); mpz_mul_mod(c, c, base, n);

        /* if fault injected : result = 1 (or random) and returns*/
        if(mpz_cmp(R[2], c) != 0){
            mpz_set_ui(result, 1);
            /* clear memory */
            mpz_clears(R[0], R[1], R[2], base, c, NULL);
            return;
        }
    }
    mpz_set(result, R[0]);

    /* clear memory */
    mpz_clears(R[0], R[1], R[2], base, c, NULL);
}

/* regular modular exp, cost : 1 Square + 1 Mult per exponent bit
left-to-right, safe.
without detection of faults attacks */
void Montgomery_ladder(mpz_t result, const mpz_t m, const mpz_t d, const mpz_t n){
    mpz_t R[2], base, c;
    mpz_inits(R[0], R[1], base, c, NULL);

    /* copy base = m mod n (ensure 0 <= base < n) */
    mpz_mod(base, m, n);
    
    /* R[0] <- 1 */
    mpz_set_ui(R[0], 1);

    /* R[1] <- m */
    mpz_set(R[1], base);

    /* find number of bits in exponent d */
    size_t nbits = mpz_sizeinbase(d, 2);
    if (nbits == 0) { /* exponent == 0 */
        mpz_set_ui(result, 1);
        mpz_clears(R[0], R[1], base, NULL);
        return;
    }

    /* process bits from most-significant to least-significant (left-to-right) */
    for (ssize_t i = nbits - 1; i >= 0; --i) {
        /* R[1 - d_i] <- R0 x R1 % n (mult) va dans R[0] ssi d_i == 1 */
        mpz_mul_mod(R[1 - mpz_tstbit(d, i)], R[0], R[1], n); 
        /* Rdi <- Rdi x Rdi % n (square) */
        mpz_mul_mod(R[mpz_tstbit(d, i)], R[mpz_tstbit(d, i)], R[mpz_tstbit(d, i)], n);
    }

    mpz_set(result, R[0]);

    /* clear memory */
    mpz_clears(R[0], R[1], base, c, NULL);
}

/* regular modular exp, cost : 1 Square + 1 Mult per exponent bit
left-to-right, safe.
R1 == R0 × m mod n allows detection of faults attacks */
void Montgomery_ladder_fault(mpz_t result, const mpz_t m, const mpz_t d, const mpz_t n){
    mpz_t R[2], base, c;
    mpz_inits(R[0], R[1], base, c, NULL);

    /* copy base = m mod n (ensure 0 <= base < n) */
    mpz_mod(base, m, n);
    
    /* R[0] <- 1 */
    mpz_set_ui(R[0], 1);

    /* R[1] <- m */
    mpz_set(R[1], base);

    /* find number of bits in exponent d */
    size_t nbits = mpz_sizeinbase(d, 2);
    if (nbits == 0) { /* exponent == 0 */
        mpz_set_ui(result, 1);
        mpz_clears(R[0], R[1], base, NULL);
        return;
    }

    /* process bits from most-significant to least-significant (left-to-right) */
    for (ssize_t i = nbits - 1; i >= 0; --i) {
        /* R[1 - d_i] <- R0 x R1 % n (mult) va dans R[0] ssi d_i == 1 */
        mpz_mul_mod(R[1 - mpz_tstbit(d, i)], R[0], R[1], n); 
        /* Rdi <- Rdi x Rdi % n (square) */
        mpz_mul_mod(R[mpz_tstbit(d, i)], R[mpz_tstbit(d, i)], R[mpz_tstbit(d, i)], n);

        /* safe error analysis prevent */
        /* c = R0 x R1 x m mod n */
        mpz_mul_mod(c, R[0], base, n);

        /* if fault injected : result = 1 (or random) and returns*/
        if(mpz_cmp(R[1], c) != 0){
            mpz_set_ui(result, 1);
            /* clear memory */
            mpz_clears(R[0], R[1], base, c, NULL);
            return;
        }
    }

    mpz_set(result, R[0]);

    /* clear memory */
    mpz_clears(R[0], R[1], base, c, NULL);
}



/* regular modular exp, cost : 1 Square + 1 Mult per exponent bit
right-to-left counterpart of the Montgomery ladder.
without detection of faults attacks */
void Joye_ladder(mpz_t result, const mpz_t m, const mpz_t d, const mpz_t n){
    mpz_t R[2], base;
    mpz_inits(R[0], R[1], base, NULL);

    /* copy base = m mod n (ensure 0 <= base < n) */
    mpz_mod(base, m, n);
    
    /* R[0] <- 1 */
    mpz_set_ui(R[0], 1);

    /* R[1] <- m */
    mpz_set(R[1], base);

    /* find number of bits in exponent d */
    size_t nbits = mpz_sizeinbase(d, 2);
    if (nbits == 0) { /* exponent == 0 */
        mpz_set_ui(result, 1);
        mpz_clears(R[0], R[1], base, NULL);
        return;
    }

    /* process bits from most-significant to least-significant (left-to-right) */
    for (size_t i = 0; i < nbits; i++) {
        /* R_1−di ← R^2_1−di × R_di mod n */
        mpz_mul_mod(R[1 - mpz_tstbit(d, i)], R[1 - mpz_tstbit(d, i)], R[1 - mpz_tstbit(d, i)], n);
        mpz_mul_mod(R[1 - mpz_tstbit(d, i)], R[1 - mpz_tstbit(d, i)], R[mpz_tstbit(d, i)], n);
    }

    mpz_set(result, R[0]);

    /* clear memory */
    mpz_clears(R[0], R[1], base, NULL);
}



/* test python : 
m=9876543210987654321
e=1234567890123456789
n=18446744073709551557 
expected=3593709867514795551

print(pow(m, e, n) == expected)
True */

/* tests for modular exp methods */
int test_exp(){
    mpz_t m, n, e, expected;
    mpz_inits(m, n, e, expected, NULL);
    mpz_set_ui(m, 9876543210987654321UL);
    mpz_set_ui(e, 1234567890123456789UL);
    mpz_set_ui(n, 18446744073709551557UL);
    mpz_set_ui(expected, 3593709867514795551UL);

    mpz_t result;
    mpz_init(result);

    /* square and mult left to right */
    square_and_muliply_left_to_right(result, m, e, n);
    if(mpz_cmp(result, expected) == 0){ // mpz_cmp return 0 iff result == expected
        printf("square and mult left to right OK \n");
    } else{
        printf("PROBLEM square and mult left to right \n");
        return 1;
    }

    /* square and mult right to left */
    square_and_muliply_right_to_left(result, m, e, n);
    if(mpz_cmp(result, expected) == 0){ // mpz_cmp return 0 iff result == expected
        printf("square and mult right to left OK \n");
    } else{
        printf("PROBLEM square and mult right to left \n");
        return 1;
    }

    /* square and mult always left to right */
    square_and_muliply_always_left_to_right(result, m, e, n);
    if(mpz_cmp(result, expected) == 0){ // mpz_cmp return 0 iff result == expected
        printf("square and mult always left to right OK \n");
    } else{
        printf("PROBLEM square and mult always left to right \n");
        return 1;
    }

    /* square and mult always right to left */
    square_and_muliply_always_right_to_left(result, m, e, n);
    if(mpz_cmp(result, expected) == 0){ // mpz_cmp return 0 iff result == expected
        printf("square and mult always right to left OK \n");
    } else{
        printf("PROBLEM square and mult always right to left \n");
        return 1;
    }

    /* Montgomery Ladder */
    Montgomery_ladder(result, m, e, n);
    if(mpz_cmp(result, expected) == 0){ // mpz_cmp return 0 iff result == expected
        printf("Montgomery Ladder OK \n");
    } else{
        printf("PROBLEM Montgomery Ladder \n");
        return 1;
    }

    /* Montgomery Ladder with fault prevention */
    Montgomery_ladder_fault(result, m, e, n);
    if(mpz_cmp(result, expected) == 0){ // mpz_cmp return 0 iff result == expected
        printf("Montgomery Ladder with fault prevention OK \n");
    } else{
        printf("PROBLEM Montgomery Ladder with fault prevention \n");
        return 1;
    }

    /* Joye Ladder */
    Joye_ladder(result, m, e, n);
    if(mpz_cmp(result, expected) == 0){ // mpz_cmp return 0 iff result == expected
        printf("Joye Ladder OK \n");
    } else{
        printf("PROBLEM Joye Ladder \n");
        return 1;
    }

    mpz_clears(m, n, e, expected, result, NULL);

    return 0;
}


/* 
int main(void){
    return test_exp();
}
*/

