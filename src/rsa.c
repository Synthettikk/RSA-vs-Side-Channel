/* dans le main on comparera les temps d'exec entre notre rsa secure et un naif */

#include "../includes/rsa.h"
#include "../includes/blinding.h"
#include "../includes/gen_primes.h"
#include "../includes/modular_exp.h"
#include <assert.h>
#include <stdio.h>


void public_key_init(public_key *k){ 
    mpz_init(k->N); 
    mpz_init(k->e); 
}

void public_key_clear(public_key *k){ 
    mpz_clear(k->N); 
    mpz_clear(k->e); 
}

void private_key_init(private_key *k){
    mpz_init(k->N); 
    mpz_init(k->phi_N); 
    mpz_init(k->d); 
}

void private_key_clear(private_key *k){ 
    /* zeroisation (pas safe à cause de gmp mais mieux que rien) */
    mpz_set_ui(k->N, 0);
    mpz_set_ui(k->phi_N, 0);
    mpz_set_ui(k->d, 0);

    mpz_clear(k->N); 
    mpz_clear(k->phi_N); 
    mpz_clear(k->d); 
}


/* gen un couple (pk, sk) avec size la taille en bits voulue pour le module N*/
int RSA_Key_Gen(public_key *pk, private_key *sk, size_t size, gmp_randstate_t randstate){
    mpz_t p, q, N, phi_N, E, d;
    mpz_inits(p, q, N, phi_N, E, d, NULL);

    /* generation de p et q de taille ~ size/2*/
    size_t size_p = size / 2;
    size_t size_q= size - size_p;
    int is_p = -1;
    int is_q = -1;
    while(is_p != 0 || is_q != 0){
        is_p = gen_prime(randstate, size_p, p);
        is_q = gen_prime(randstate, size_q, q);
    }

    /* N = pq */
    mpz_mul(N, p, q);

    /* phi_N = (p - 1)(q - 1) */
    mpz_t p_1, q_1;
    mpz_inits(p_1, q_1, NULL);
    mpz_sub_ui(p_1, p, 1); mpz_sub_ui(q_1, q, 1);
    mpz_mul(phi_N, p_1, q_1); // phi_N = p_1 * q_1

    /* clear secrets */
    mpz_set_ui(p_1, 0); mpz_set_ui(q_1, 0); mpz_set_ui(p, 0); mpz_set_ui(q, 0); // zeroisation pas sûre (gmp...) 
    mpz_clears(p_1, q_1, p, q, NULL);

    /* E = 65537 hardcodé */
    mpz_set_ui(E, 65537);

    /* d = E^-1 mod phi_N */
    if(mpz_invert(d, E, phi_N) == 0){
        /* clear */
        mpz_set_ui(phi_N, 0); mpz_set_ui(d, 0); // zeroisation pas sûre (gmp...) 
        mpz_clears(N, phi_N, E, d, NULL);
        return 0; // echec
    } 

    /* met dans la clé */
    mpz_set(pk->e, E); mpz_set(pk->N, N);
    mpz_set(sk->N, N); mpz_set(sk->phi_N, phi_N); mpz_set(sk->d, d);

    /* clear */
    mpz_set_ui(phi_N, 0); mpz_set_ui(d, 0); // zeroisation pas sûre (gmp...) 
    mpz_clears(N, phi_N, E, d, NULL);

    return 1;
}

/* result = m^e mod N*/
void RSA_Encrypt(mpz_t result, mpz_t const m, const public_key *pk){

    /* pas besoin de masquage pour chiffrer : c'est une opération publique */

    /* pas besoin de montgomery ladder non plus (public) */
    /* il faudrait un salage pour rendre rsa non déterministe (pas facile à bien faire) */

    mpz_powm(result, m, pk->e, pk->N); // on aurait aussi pu prendre notre propre square and mult mais gmp est censé être opti

}

/* result <- c^d mod n*/
void RSA_Decrypt(mpz_t result, const mpz_t c, const public_key *pk,  const private_key *sk, gmp_randstate_t state){
    /* init (besoin de copies car les blindings modifient en place) */
    mpz_t r_inv, N_prime;
    mpz_inits(r_inv, N_prime, NULL);
    mpz_t c_masked; mpz_init_set(c_masked, c); // copie le cipher c
    mpz_t d_masked; mpz_init_set(d_masked, sk->d); // copie le secret d

    /* opération privée : masquage */
    blinding_message(state, c_masked, pk->e, pk->N, r_inv);
    blinding_exponent(state, d_masked, sk->phi_N);
    blinding_modulus(pk->N, N_prime, state);

    /* Montgomery Ladder */
    Montgomery_ladder_fault(result, c_masked, d_masked, sk->N);

    /* démasque module */
    mpz_mod(result, result, pk->N);
    /* démasque le message */
    unblinding_message(result, r_inv, sk->N);

    mpz_set_ui(r_inv, 0); mpz_set_ui(N_prime, 0); mpz_set_ui(c_masked, 0); mpz_set_ui(d_masked, 0);
    mpz_clears(c_masked, d_masked, r_inv, N_prime, NULL);
}

/* result <- m^d mod n */
void RSA_Sign(mpz_t result, const mpz_t m, const public_key *pk, const private_key *sk, gmp_randstate_t state){
    /* init (besoin de copies car les blindings modifient en place) */
    mpz_t r_inv, N_prime;
    mpz_inits(r_inv, N_prime, NULL);
    mpz_t m_masked; mpz_init_set(m_masked, m); // copie le message m
    mpz_t d_masked; mpz_init_set(d_masked, sk->d); // copie le secret d

    /* opération privée : masquage */
    blinding_message(state, m_masked, pk->e, pk->N, r_inv);
    blinding_exponent(state, d_masked, sk->phi_N);
    blinding_modulus(pk->N, N_prime, state);

    /* Montgomery Ladder */
    Montgomery_ladder_fault(result, m_masked, d_masked, sk->N);

    /* démasque module */
    mpz_mod(result, result, pk->N);
    /* démasque le message */
    unblinding_message(result, r_inv, sk->N);

    /* clear */
    mpz_set_ui(r_inv, 0); mpz_set_ui(N_prime, 0); mpz_set_ui(m_masked, 0); mpz_set_ui(d_masked, 0);
    mpz_clears(m_masked, d_masked, r_inv, N_prime, NULL);
}

/* Vérifie avec la pk si le message a bien été signé avec la sk : renvoie 0 ssi OK */
int RSA_Verif(const mpz_t m, const mpz_t s, const public_key *pk){

    /* pas besoin de masquage pour chiffrer : c'est une opération publique */

    /* pas besoin de montgomery ladder non plus (public) */

    mpz_t got;
    mpz_init(got);

    mpz_powm(got, s, pk->e, pk->N); // pk->e <=> (*pk).e

    int verif = mpz_cmp(got, m);

    mpz_clear(got);

    return verif;
}

/* renvoie 1 si ok */
int test_rsa(gmp_randstate_t state){
    int ok = 1;

    public_key pk; private_key sk;
    public_key_init(&pk); private_key_init(&sk);

    /* Génération 1024 bits (pour test rapide). Adapter à 2048+ en prod */
    int ret = RSA_Key_Gen(&pk, &sk, 1024, state);
    assert(ret == 1);
    printf("KeyGen OK \n");

    /* Choix d'un message m < N */
    mpz_t m, c, dec, sig;
    mpz_inits(m, c, dec, sig, NULL);

    /* m = 42 */
    mpz_set_ui(m, 42);
    assert(mpz_cmp(m, pk.N) < 0);

    /* Chiffrement / déchiffrement */
    RSA_Encrypt(c, m, &pk);
    RSA_Decrypt(dec, c, &pk, &sk, state);
    assert(mpz_cmp(dec, m) == 0);
    printf("Encrypt / Decrypt OK \n");

    /* Signature / vérif */
    RSA_Sign(sig, m, &pk, &sk, state);
    int ver = RSA_Verif(m, sig, &pk);
    assert(ver == 0); /* 0 == OK */
    printf("Sign / Verif OK \n");

    /* Test d'inversion d'un message différent pour éviter faux positifs */
    mpz_set_ui(m, 43);
    RSA_Encrypt(c, m, &pk);
    RSA_Decrypt(dec, c, &pk, &sk, state);
    assert(mpz_cmp(dec, m) == 0);

    /* cleanup */
    mpz_clears(m, c, dec, sig, NULL);
    public_key_clear(&pk); private_key_clear(&sk);

    return ok;
}
