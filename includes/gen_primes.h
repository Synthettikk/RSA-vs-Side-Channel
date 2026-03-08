#ifndef gen_primes_h
#define gen_primes_h

#include <stddef.h> // pour le size_t
#include <gmp.h> 


/* Récupère une seed sûre depuis l'entropie système et la met dans state 
ne laisse rien en RAM sauf si mlock échoue
renvoie 0 si succès, -1 sinon */
int crypto_seed(gmp_randstate_t state, size_t seed_bytes);


// Génère un nombre aléatoire de la taille spécifiée en bits
int gen_big_int_b(gmp_randstate_t state, size_t bits, mpz_t result);

// Génère un nombre aléatoire < n
int gen_big_int_m(gmp_randstate_t state, const mpz_t n, mpz_t result);


// Génère un nombre premier aléatoire de la taille spécifiée en bits : renvoie 0 si reussite, -1 sinon
int gen_prime(gmp_randstate_t state, size_t bits, mpz_t result);


// genere un certain nombre de premiers et vérifie s'ils sont bien premiers, de la bonne taille, et que le code ne renvoie pas d'erreur
int test_primes(gmp_randstate_t randstate, int nb_primes, size_t size);


#endif // gen_primes_h