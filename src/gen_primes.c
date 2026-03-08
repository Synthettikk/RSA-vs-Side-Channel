// ici on va faire la routine qui genere des premiers le plus secure qu'on peut : 

// on va utiliser gmp

// pour la seed : recupere depuis l'entropie de la machine : 
// lire N octets depuis /dev/urandom -> mpz_import(seed_mpz) -> gmp_randseed(state, seed_mpz)
// ensuite on genere un nb urandom entre 1 et N de k bits
//    mpz_urandomb(p, state, bits);
//    mpz_setbit(p, bits-1); mpz_setbit(p, 0); // MSB=1, LSB=1 pour avoir le bon nb de bits et etre impair

// miller-rabin -> on va utiliser la fct de gmp : mpz_probab_prime_p(p, reps) entre 25 et 64 reps

// si pas premier, on recommence la gen

// si tout ok : accept p, sinon regenere
// re-seeder tous les 2^20 gen et tous les 10000 echecs d'affilé 

// nettoyer la mémoire qui contient des données sensibles comme le state ou la seed : mpz_clear


// PSEUDO CODE : 

// 1) seed: lire N = 32 - 64 octets depuis /dev/urandom -> mpz_import(seed_mpz) -> gmp_randseed(state, seed_mpz)
// 2) boucle:
//    mpz_urandomb(p, state, bits);
//    mpz_setbit(p, bits-1); mpz_setbit(p, 0); // MSB=1, LSB=1
//    if (is_divisible_by_small_primes(p)) continue;
//    mpz_sub_ui(tmp, p, 1); mpz_fdiv_q_ui(q, tmp, 2);
//    if (is_divisible_by_small_primes(q)) continue;
//    if (mpz_probab_prime_p(q, reps) == 0) continue;
//    if (mpz_probab_prime_p(p, reps) == 0) continue;
//    // accept p

/* On utilise mlock pour empecher le swap de la RAM sur le disque : 

Le swap (ou pagination sur disque) est un espace disque utilisé par 
le système d'exploitation pour étendre la mémoire physique (RAM). 
Quand la RAM est pleine ou pour optimiser l'utilisation, le noyau 
copie des pages mémoire inactives sur disque (fichier ou partition swap). 
Ces pages peuvent contenir n'importe quelles données d'un processus 
— y compris des secrets — et rester sur disque jusqu'à leur écrasement. */

#define _GNU_SOURCE

#include "../includes/gen_primes.h"
#include <sys/random.h> // pour entropie systeme
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h> // pour mlock etc -> gestion mémoire safe
#include <stdio.h>
#include <gmp.h>


/* portable secure zero: use explicit_bzero if available, else volatile memset 
version safe de     memset(buf, 0, seed_bytes); */
static void secure_zero(void *p, size_t n){
#if defined(HAVE_EXPLICIT_BZERO) || (_POSIX_C_SOURCE >= 200809L && !defined(__ANDROID__))
    explicit_bzero(p, n);
#else
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while(n--) *vp++ = 0;
#endif
}


/* Récupère une seed sûre depuis l'entropie système et la met dans state 
ne laisse rien en RAM sauf si mlock échoue
renvoie 0 si succès, -1 sinon */
int crypto_seed(gmp_randstate_t state, size_t seed_bytes){
    if(seed_bytes == 0) return -1;

    // buf = pointeur vers la zone memoire qui va stocker les octets lus dans sys/random
    // on alloue cette zone mémoire : 
    unsigned char *buf = NULL; 
    buf = malloc(seed_bytes);
    if(buf == NULL) return -1; // gestion erreur -> échec
    /* touch page to satisfy static analyzer (no secret written yet) */
    if (seed_bytes > 0) ((volatile unsigned char *)buf)[0] = 0;

    /* Tente de verrouiller la mémoire pour éviter le swap */
    if (mlock(buf, seed_bytes) != 0){
        /* Si mlock échoue, on peut choisir d'échouer plutôt que d'exposer la seed en swap.
           Ici on échoue explicitement. */
        secure_zero(buf, seed_bytes);
        free(buf);
        return -1;
    }

    // utilise getrandom pour recup seed_bytes octets depuis le random systeme
    // en fait getrandom peut ecrire moins d'octets que demandé en cas d'interruption/erreur donc on va boucler par sécurité
    /* Lit exactement seed_bytes octets depuis l'entropie système */
    size_t total = 0;
    while (total < seed_bytes){
        ssize_t r = getrandom(buf + total, seed_bytes - total, 0);
        if (r < 0){
            if (errno == EINTR) continue;
            /* erreur fatale : effacer et libérer */
            secure_zero(buf, seed_bytes);
            munlock(buf, seed_bytes);
            free(buf);
            return -1;
        }
        if (r == 0){
            /* getrandom retournant 0 dans ce contexte est anormal -> échec */
            secure_zero(buf, seed_bytes);
            munlock(buf, seed_bytes);
            free(buf);
            return -1;
        }
        total += (size_t)r;
    }

    // construction de la seed gmp à partir du random obtenu
    mpz_t seed_mpz;
    mpz_init(seed_mpz);
    mpz_import(seed_mpz, seed_bytes, 1, 1, 0, 0, buf); // convertit en mpz_t les octets qui sont dans buf
    gmp_randseed(state, seed_mpz); // met la seed dans le state

    // efface la mémoire pour pas laisser fuiter la seed
    /* Efface les représentations sensibles :
       - efface le mpz interne si possible en le mettant explicitement à zéro avant clear
       - efface le buffer lui-même, unlock, free */
    mpz_set_ui(seed_mpz, 0); /* réduit la valeur ; n'efface pas forcément les tampons internes alloués par GMP */
    mpz_clear(seed_mpz);

    secure_zero(buf, seed_bytes);
    munlock(buf, seed_bytes);
    free(buf);

    //reussite
    return 0;
}

// Génère un nombre aléatoire de la taille spécifiée en bits
int gen_big_int_b(gmp_randstate_t state, size_t bits, mpz_t result){
    mpz_urandomb(result, state, bits);
    mpz_setbit(result, bits-1); // force MSB -> result a le bon nb de bits
    return 0;
}

// Génère un nombre aléatoire < n
int gen_big_int_m(gmp_randstate_t state, const mpz_t n, mpz_t result){
    mpz_urandomm(result, state, n);
    return 0;
}

/* renvoie 0 si reussite, -1 sinon */
int gen_prime(gmp_randstate_t state, size_t bits, mpz_t result){
    int cmp = 0;
    while(cmp < 100000){
        gen_big_int_b(state, bits, result);
        mpz_setbit(result, 0); // force le LSB à 1 -> result impair
        /* mpz_probab_prime_p: 0=composite, 1=probable prime, 2=definitely prime */
        int r = mpz_probab_prime_p(result, 40); // 40 reps (largement suffisant, fait deja un crible)
        if (r > 0) return 0; // reussite
        // sinon recommence
        cmp += 1;
    }
    // ici on pourrait reseeder si on veut 
    return -1;
}


// genere un certain nombre de premiers et vérifie s'ils sont bien premiers, de la bonne taille, et que le code ne renvoie pas d'erreur
int test_primes(gmp_randstate_t randstate, int nb_primes, size_t size){
    mpz_t prime;
    mpz_init(prime);
    for(int i = 0; i < nb_primes; i++){

        if(gen_prime(randstate, size, prime) != 0){ // si gen_prime a échoué
            mpz_clear(prime);
            return 0;
        }

        // affichage
        printf("Nombre généré : ");
        gmp_printf("%Zd\n", prime); 

        size_t size_prime = mpz_sizeinbase(prime, 2);
        printf("Taille en bits : %zu\n", size_prime);
        if(size_prime != size){
            mpz_clear(prime);
            return 0;
        }

        int is_probable = mpz_probab_prime_p(prime, 100); /* renvoie 0/1/2 */
        printf("Premier ? : %d\n", is_probable);
        if(is_probable == 0){
            mpz_clear(prime);
            return 0;
        }

        printf("\n");
    }

    mpz_clear(prime);
    return 1;
}


// a priori la gestion du re-seed se fera dans le main (à voir si on a besoin d'ajouter des compteurs ici)
