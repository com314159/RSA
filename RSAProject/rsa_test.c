//
//  rsa_test.c
//  RSAProject
//
//  Created by guozhicheng on 5/9/16.
//  Copyright © 2016 guozhicheng. All rights reserved.
//

#include "rsa_test.h"
#include "rsa.h"
#include "ctr_drbg.h"

 void testprint()
{
    printf("测试");
    
    
    
    
}


void generateRSAKeys() {
    
    int ret;
    
    mbedtls_rsa_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    FILE *fpub = NULL;
    FILE *fpriv = NULL;
    
    const char *pers = "c_generateKeys_rsa";
    
    mbedtls_ctr_drbg_init(&ctr_drbg);
    fflush(stdout);
    
    mbedtls_entropy_init( &entropy );
    
//    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers,strlen( pers ) ) ) != 0 ) {
//        
//    }
    
    
}