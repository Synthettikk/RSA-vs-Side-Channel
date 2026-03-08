// Ici on fera les tests qui verifient si le rsa/gen_primes/etc fonctionne

#include "../includes/gen_primes.h"
#include "../includes/modular_exp.h"
#include "../includes/blinding.h"
#include "../includes/rsa.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>



int main(){
    
    // init l'état RNG de gmp -> à mettre dans le main (on le clear à la fin du main)
    gmp_randstate_t randstate;
    gmp_randinit_default(randstate);

    // TEST DE LA CRYPTO SEED
    if(crypto_seed(randstate, 64) == 0){
        printf("CRYPTO SEED OK \n");
    } else{
        printf("PROBLEME AVEC CRYPTO SEED \n");
    }
    
    // TESTS DE LA GENERATION DE PREMIERS (OK)
    if(test_primes(randstate, 10, 1024)){
        printf("GENERATION DE PREMIERS REUSSIE \n");
    } else{
        printf("GENERATION DE PREMIERS A ECHOUÉ \n");
    }    
    
    // TESTS DES EXP MODULAIRES (OK)
    if(test_exp() == 0){
        printf("TESTS DES EXPONENTIATIONS REUSSIS \n");
    } else{
        printf("TESTS DES EXPONENTIATIONS A ECHOUÉ \n");
    }
    
    // TESTS DES MASQUAGES (OK)
    if(test_blinding(randstate) == 0){
        printf("TESTS DES MASQUAGES REUSSIS \n");
    } else{
        printf("TESTS DES MASQUAGES A ECHOUÉ \n");
    }

    // TEST DES PRIMITIVES RSA (OK)
    if(test_rsa(randstate)){
        printf("TESTS RSA REUSSIS \n");
    } else{
        printf("TESTS RSA A ECHOUÉ \n");
    }
    
    // nettoyage mémoire
    gmp_randclear(randstate);
    return 0;
}