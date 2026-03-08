#include "gmp.h"

typedef struct { mpz_t N, e; } public_key;
typedef struct { mpz_t N, d, phi_N; } private_key; // on met phi_n dans la sk pour le masquage d'exp

/* inits & clears */
void public_key_init(public_key *k);
void public_key_clear(public_key *k);
void private_key_init(private_key *k);
void private_key_clear(private_key *k);

/* gen un couple (pk, sk) avec size la taille en bits voulue pour le module N*/
int RSA_Key_Gen(public_key *pk, private_key *sk, size_t size, gmp_randstate_t randstate);

/* result = m^e mod N*/
void RSA_Encrypt(mpz_t result, mpz_t const m, const public_key *pk);

/* result <- c^d mod n*/
void RSA_Decrypt(mpz_t result, const mpz_t c, const public_key *pk,  const private_key *sk, gmp_randstate_t state);

/* result <- m^d mod n */
void RSA_Sign(mpz_t result, const mpz_t m, const public_key *pk, const private_key *sk, gmp_randstate_t state);

/* Vérifie avec la pk si le message a bien été signé avec la sk : renvoie 0 ssi OK */
int RSA_Verif(const mpz_t m, const mpz_t s, const public_key *pk);

int test_rsa(gmp_randstate_t state);
