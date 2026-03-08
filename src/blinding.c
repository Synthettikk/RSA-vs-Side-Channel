/* 
Les masquages (blindings) se font toujours du côté du détenteur de la 
clé privée, lors des opérations qui la manipulent, afin de la protéger.
Concrètement : on masque avant de déchiffrer/signer 
puis on démasque juste après, avant d'envoyer le résultat.

Masquage de message : 
- on choisit r random entre 0 et n, inversible mod n
- masquer : m' = (m * r^e) mod n
- calcul privé : s' = (m')^d mod n = m^d * r mod n
- démasquer : s = s' * r^{-1} mod n = m^d mod n
Surcoût : demande de calculer r^e mod n (même coût qu'un chiffrement : O(n^2)) et r^-1 mod n 
(coûte << qu'une exp modulaire : O(n^3) grâce à des optimisations de gmp)
Notons qu'on utilise un masquage multiplicatif du message 
(et non additif : m' = m + rn car ca disparait dès le premier mod n)
-> Protège contre les attaques qui tentent de prédire des valeurs
intermédiaires pendant l'exponentiation, en particulier les attaques par faute.

Masquage d'exposant : 
- on choisit k random entre 0 et n
- d' = d + k phi(n)
- s = m^d mod n = m^d' mod n par Euler
Pas de surcoût car d' a environ le même nombre de bits que d
-> Protège contre les attaques side-chanel qui utilisent plusieurs traces (DPA, CPA, ...): 
les traces sont alors toutes différentes car r est différent à chaque fois.

Masquage de module:
- on choisit r random entre 0 et n, concrètement on prend r pas trop grand 
pour ne pas trop alourdir les calculs (128 bits max)
- N' = rN puis on fait les calculs mod N'
- pour démasquer il suffit de réduire mod N le résultat
Preuve que cela fonctionne 
(Pour tout entier x et tout N' = r·N (r entier ≥ 1),
(x mod N') mod N = x mod N.) : 
x ≡ x mod N' (mod N'), donc x − (x mod N') est multiple de N' donc multiple de N, donc x ≡ x mod N' (mod N). Ainsi les restes modulo N coïncident.

masquage message -> module -> démasquage module -> message
*/


#include "../includes/blinding.h"
#include "../includes/gen_primes.h"
#include <stdio.h>
#include "gmp.h"

/* m' = (m * r^e) mod n avec r random entre 0 et n inversible mod MODIFIE L'ENTRÉE m */
void blinding_message(gmp_randstate_t state, mpz_t m, const mpz_t e, const mpz_t n, mpz_t r_inv){
    mpz_t r; mpz_init(r);
    /* tant que r est pas inv mod n on regen r */
    while(1){
        gen_big_int_m(state, n, r);
        if(mpz_invert(r_inv, r, n)) break;
    }

    /* masquage : m' = (m * r^e) mod n*/
    mpz_t r_e; mpz_init(r_e);
    mpz_powm(r_e, r, e, n); // r_e <- r^e mod n (calcul publique : pas besoin d'une exp reg)
    mpz_mul(m, m, r_e); // m <- m x r^e
    mpz_mod(m, m, n); // m %= n

    mpz_clears(r, r_e, NULL);
}

// démasquer : s = s' * r^{-1} mod n = m^d mod n car s' = (m')^d mod n = m^d * r mod n MODIFIE L ENTREE s
void unblinding_message(mpz_t s, mpz_t r_inv, const mpz_t n){
    mpz_mul(s, s, r_inv); // s <- s.r^-1
    mpz_mod(s, s, n); // s =% n
}

/* N' = rN, r de 128bits, ne modifie pas l'entrée N, modifie N' */
void blinding_modulus(const mpz_t N, mpz_t N_prime, gmp_randstate_t randstate){
    /* gen r random de 128 bits, 
    concretement on prefere que pgcd(r, N) = 1 
    pour pas modifier la structure factorielle
    -> toujours vrai si N = pq avec p et q de + de 128bits 
    (dans ce cas il ne peut pas y avoir de facteur commun) */
    mpz_t r; mpz_init(r);
    mpz_urandomb(r, randstate, 128); // k de 128 bits est suffisant (l'augmenter améliore quasi pas la sécu)
    /* évite r == 0 */
    while (mpz_cmp_ui(r, 0) == 0) {
        mpz_urandomb(r, randstate, 128);
    }
    /* N' <- rN */
    mpz_mul(N_prime, r, N);

    /* clear */
    mpz_set_ui(r, 0);
    mpz_clear(r);
}

/* d' = d + k phi(n) et s = m^d mod n = m^d' mod n par Euler, pas besoin d'unmask MODIFIE L ENTREE d*/
void blinding_exponent(gmp_randstate_t state, mpz_t d, const mpz_t phi_n){
    mpz_t k, tmp;
    mpz_inits(k, tmp, NULL);

    mpz_urandomb(k, state, 128); // k de 128 bits est suffisant (l'augmenter améliore quasi pas la sécu)
    /* évite k == 0 */
    while (mpz_cmp_ui(k, 0) == 0) {
        mpz_urandomb(k, state, 128);
    }

    /* tmp = k * phi_n */
    mpz_mul(tmp, k, phi_n);

    /* d = d + tmp */
    mpz_add(d, d, tmp);

    /* clear */
    mpz_set_ui(k, 0);
    mpz_clears(k, tmp, NULL);
}

int test_blinding(gmp_randstate_t state){
    /* paramètres RSA très petits pour test */
    mpz_t p, q, n, n_prime, phi_n, e, d, m, m_orig, m_blinded, s_prime, s_unblinded, r_inv;
    mpz_inits(p,q,n, n_prime, phi_n, e,d,m,m_orig,m_blinded,s_prime,s_unblinded,r_inv,NULL);

    /* prendre p,q petits premiers (ex pour test) */
    mpz_set_ui(p, 10007);
    mpz_set_ui(q, 10009);
    mpz_mul(n, p, q);
    /* phi = (p-1)*(q-1) */
    mpz_t t1, t2;
    mpz_inits(t1, t2, NULL);
    mpz_sub_ui(t1, p, 1);
    mpz_sub_ui(t2, q, 1);
    mpz_mul(phi_n, t1, t2);

    /* public exponent e */
    mpz_set_ui(e, 65537);
    /* compute d = e^{-1} mod phi_n */
    if (mpz_invert(d, e, phi_n) == 0){
        printf("e not invertible mod phi(n)\n");
        return 1;
    }

    /* message m (1 < m < n) */
    mpz_set_ui(m_orig, 42);
    mpz_set(m, m_orig); /* m sera modifié par blinding_message */

    /* test blinding_message */
    blinding_message(state, m, e, n, r_inv);
    mpz_set(m_blinded, m);

    /* simulate signer: s' = (m')^d mod n */
    mpz_powm(s_prime, m_blinded, d, n);

    /* unblind */
    mpz_set(s_unblinded, s_prime);
    unblinding_message(s_unblinded, r_inv, n);

    /* verification: s_unblinded^e mod n == m_orig */
    mpz_t verify; mpz_init(verify);
    mpz_powm(verify, s_unblinded, e, n);

    if (mpz_cmp(verify, m_orig) == 0){
        gmp_printf("TEST OK: signature verified. m = %Zd\n", m_orig);
    } else {
        gmp_printf("TEST FAIL:\n expected m = %Zd\n got      = %Zd\n", m_orig, verify);
    }

    /* test blinding_exponent: take d2 = d and blind it */
    mpz_t d2, s2;
    mpz_inits(d2, s2, NULL);
    mpz_set(d2, d);
    blinding_exponent(state, d2, phi_n);

    /* s2 = m_orig ^ d2 mod n  should equal m_orig^d mod n */
    mpz_powm(s2, m_orig, d2, n);
    mpz_t s_expected; mpz_init(s_expected);
    mpz_powm(s_expected, m_orig, d, n);

    if (mpz_cmp(s2, s_expected) == 0){
        gmp_printf("EXPONENT BLINDING OK\n");
    } else {
        gmp_printf("EXPONENT BLINDING FAIL\n");
    }

    /* test blinding_modulus */
    blinding_modulus(n, n_prime, state);
    /* s2 = m_orig ^ d mod n' mod should equal m_orig ^ d mod n */
    mpz_powm(s2, m_orig, d, n_prime);
    mpz_mod(s2, s2, n); // unmask = reduce mod n

    if (mpz_cmp(s2, s_expected) == 0){
        gmp_printf("MODULUS BLINDING OK\n");
    } else {
        gmp_printf("MODULUS BLINDING FAIL\n");
    }
    

    /* clear */
    mpz_clears(p,q,n, n_prime, phi_n,e,d,m,m_orig,m_blinded,s_prime,s_unblinded,r_inv,t1,t2,verify,d2,s2,s_expected,NULL);

    return 0;
}
