// Le but est de coder un RSA résistant aux attaques de side channel classiques 
// comme la SPA, DPA, CPA
// on va utiliser les contre mesures vues en cours : 
// square and mult régulier : Montgomery Ladder cest pas mal (voir la Joyes ladder ou autre qd mm)
// verif en sortie pour tester s'il y a eu injection de faute 
// on va faire du blinding (masquage) d'exposant (protege contre les attaques qui utilisent plusieurs traces de courant -> chaque trace sera 
// différente car l'exp d' sera à chaque fois différent), de module (permet de masquer les résultats intermédiaires dans l'exp), et de 
// message (coûte 0 surcout et améliore le masquage de module, inutile sans masquage de module car disparait au premier mod N)

// Reste le danger de la timing analysis : 
// on va utiliser gmp qui n'est pas Constant Time
// refaire un gmp-like pour les operations arithmetiques de base est faisable mais difficile et demande de refaire bcp de choses : 
// tous les types seraient modifiés, les masquages modifient les tailles -> demande des adaptations pour le CT...
// on va plutot preferer rester avec gmp et tenter une timing analysis pour évaluer gmp et tenter d'exhiber ses faiblesses non CT

// A priori on fera pas le CRT, ou peut etre plus tard -> le CRT permet un dechiffrement 4 fois 
// plus rapide en theorie mais augmente les possibilité d'attaques et complique les masquages

// On va commencer par faire le square and mult safe avec blindings 
// puis on fera la generation de clés (peut etre) -> cest pas facile de faire la gen de nbs premiers safe


// On va coder un RSA 2048 (on peut mettre ca dans une variable quitte à le changer)

// signer cest la meme opération que dechiffrer
// verifiercest la meme operation que chiffrer
// on va donc mesurer les temps que du chiffrement vs dechiffrement entre notre implem et du square and mult naif

// RESTE À :
// faire la comparaison de temps avec la montgomery ladder seule aussi et comparer avec la différence theorique
// il existe aussi un mpz_powm_sec qui fait du powm constant time : on peut le tester aussi

#define _POSIX_C_SOURCE 199309L

#include "../includes/gen_primes.h"
#include "../includes/modular_exp.h"
#include "../includes/blinding.h"
#include "../includes/rsa.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include "gmp.h"


/* Helper timing */
static double timespec_to_ms(const struct timespec *t){
    return t->tv_sec * 1000.0 + t->tv_nsec / 1e6;
}
static double diff_ms(const struct timespec *a, const struct timespec *b){
    return timespec_to_ms(a) - timespec_to_ms(b);
}

/* Benchmark one key size:
   - gen key
   - generate a random plaintext m < N
   - compute c = m^e mod N
   - run several iterations of:
       * mpz_powm(tmp, c, d, N)  (A)
       * RSA_Decrypt(tmp2, c, pk, sk, state) (B)
   returns times in ms per op via pointers
*/
int bench_one_size(size_t keybits, int iterations, double *t_mpz_powm_ms, double *t_mpz_powm_sec_ms, double *t_sq_and_mult, double *t_montgomrey_ladder_ms, double *t_montgomrey_fault_ms, double *t_rsa_decrypt_ms){
    gmp_randstate_t rng;
    gmp_randinit_default(rng);
    crypto_seed(rng, 64);
    // printf("rng init ok\n"); fflush(stdout);

    public_key pk; private_key sk;
    public_key_init(&pk); private_key_init(&sk);

    if(!RSA_Key_Gen(&pk, &sk, keybits, rng)){
        fprintf(stderr, "Key gen failed for %zu bits\n", keybits);
        return 0;
    }
    // printf("RSA_Key_Gen ok\n"); fflush(stdout);

    /* prepare message m, ciphertext c */
    mpz_t m, c, tmp;
    mpz_inits(m, c, tmp, NULL);

    /* choose random m in [2, N-2] */
    mpz_urandomm(m, rng, pk.N);
    if(mpz_cmp_ui(m, 2) < 0) mpz_set_ui(m, 2);

    /* c = m^e mod N (en utilisant mpz_powm) */
    mpz_powm(c, m, pk.e, pk.N);

    /* Warm-up */
    for(int i=0;i<5;i++){
        mpz_powm(tmp, c, sk.d, pk.N);
        RSA_Decrypt(tmp, c, &pk, &sk, rng);
    }

    struct timespec t0, t1;

    /* Measure mpz_powm */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for(int i=0;i<iterations;i++){
        mpz_powm(tmp, c, sk.d, pk.N);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double total_mpz = diff_ms(&t1, &t0);

    /* Measure mpz_powm_sec */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for(int i=0;i<iterations;i++){
        mpz_powm_sec(tmp, c, sk.d, pk.N);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double total_powm_sec = diff_ms(&t1, &t0);

    /* Measure square_and_mult */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for(int i=0;i<iterations;i++){
        square_and_muliply_right_to_left(tmp, c, sk.d, pk.N);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double total_sq_and_mult = diff_ms(&t1, &t0);

    /* Measure montgomery ladder */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for(int i=0;i<iterations;i++){
        Montgomery_ladder(tmp, c, sk.d, pk.N);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double total_montgomery = diff_ms(&t1, &t0);

    /* Measure montgomery ladder with fault prevent */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for(int i=0;i<iterations;i++){
        Montgomery_ladder_fault(tmp, c, sk.d, pk.N);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double total_montgomery_fault = diff_ms(&t1, &t0);

    /* Measure RSA_Decrypt */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for(int i=0;i<iterations;i++){
        RSA_Decrypt(tmp, c, &pk, &sk, rng);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double total_rsa = diff_ms(&t1, &t0);

    *t_mpz_powm_ms = total_mpz / iterations;
    *t_mpz_powm_sec_ms = total_powm_sec / iterations;
    *t_sq_and_mult = total_sq_and_mult / iterations;
    *t_montgomrey_ladder_ms = total_montgomery / iterations;
    *t_montgomrey_fault_ms = total_montgomery_fault / iterations;
    *t_rsa_decrypt_ms = total_rsa / iterations;

    /* cleanup */
    mpz_clears(m, c, tmp, NULL);
    public_key_clear(&pk); private_key_clear(&sk);
    gmp_randclear(rng);
    return 1;
}

int main(int argc, char **argv){
    int iterations = 30; // fera la moyenne des tmps (ms) 
    if(argc >= 2) iterations = atoi(argv[1]);

    /* Key sizes to test */
    size_t sizes[] = {2048, 2176, 2304, 2432, 2560, 2688, 2816, 2944, 3072, 3200, 3328, 3456, 3584, 3712, 3840, 3968, 4096};
    int nsizes = sizeof(sizes)/sizeof(sizes[0]);

    printf("keybits, mpz_powm_ms, mpz_powm_sec_ms, sq_and_mult, montgomery_ladder_ms, montgomery_fault_ms, rsa_decrypt_ms\n");
    for(int i=0;i<nsizes;i++){
        // printf("=== bench keysize=%zu start\n", sizes[i]); fflush(stdout);
        double t1, t2, t3, t4, t5, t6;
        if(!bench_one_size(sizes[i], iterations, &t1, &t2, &t3, &t4, &t5, &t6)){
            fprintf(stderr, "bench failed for %zu\n", sizes[i]);
        continue;
        }
        // printf("=== bench keysize=%zu done\n", sizes[i]); fflush(stdout);
        printf("%zu, %.6f, %.6f, %.6f, %.6f, %.6f, %.6f \n", sizes[i], t1, t2, t3, t4, t5, t6);
        fflush(stdout);
    }
    return 0;
}


