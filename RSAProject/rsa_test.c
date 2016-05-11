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
#include "entropy.h"

 void testprint()
{
    printf("测试生成key\n");
    
    
    
    char c = 'c';
    
    char s[] = "hello";
    
    printf("c is :%s\n",s);
}


#define KEY_SIZE   2048
#define EXPONENT   65537

void pubEncrpt() {
    
    
}


void generateRSAKeys() {
    
    int ret;
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    FILE *fpub  = NULL;
    FILE *fpriv = NULL;
    const char *pers = "rsa_genkey_rsa_video_qqq";
    
    mbedtls_ctr_drbg_init( &ctr_drbg );
    
    printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );
    
    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                      (const unsigned char *) pers,
                                      strlen( pers ) ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }
    
    printf( " ok\n  . Generating the RSA key [ %d-bit ]...", KEY_SIZE );
    fflush( stdout );
    
    mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );
    
    if( ( ret = mbedtls_rsa_gen_key( &rsa, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE,
                                    EXPONENT ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_rsa_gen_key returned %d\n\n", ret );
        goto exit;
    }
    
    printf( " ok\n  . Exporting the public  key in rsa_pub.txt...." );
    fflush( stdout );
    
    if( ( fpub = fopen( "/Users/gzc/Work/temp/rsa_pub.txt", "wb+" ) ) == NULL )
    {
        printf( " failed\n  ! could not open rsa_pub.txt for writing\n\n" );
        ret = 1;
        goto exit;
    }
    
    if( ( ret = mbedtls_mpi_write_file( "N = ", &rsa.N, 16, fpub ) ) != 0 ||
       ( ret = mbedtls_mpi_write_file( "E = ", &rsa.E, 16, fpub ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_mpi_write_file returned %d\n\n", ret );
        goto exit;
    }
    
    printf( " ok\n  . Exporting the private key in rsa_priv.txt..." );
    fflush( stdout );
    
    if( ( fpriv = fopen( "/Users/gzc/Work/temp/rsa_priv.txt", "wb+" ) ) == NULL )
    {
        printf( " failed\n  ! could not open rsa_priv.txt for writing\n" );
        ret = 1;
        goto exit;
    }
    
    if( ( ret = mbedtls_mpi_write_file( "N = " , &rsa.N , 16, fpriv ) ) != 0 ||
       ( ret = mbedtls_mpi_write_file( "E = " , &rsa.E , 16, fpriv ) ) != 0 ||
       ( ret = mbedtls_mpi_write_file( "D = " , &rsa.D , 16, fpriv ) ) != 0 ||
       ( ret = mbedtls_mpi_write_file( "P = " , &rsa.P , 16, fpriv ) ) != 0 ||
       ( ret = mbedtls_mpi_write_file( "Q = " , &rsa.Q , 16, fpriv ) ) != 0 ||
       ( ret = mbedtls_mpi_write_file( "DP = ", &rsa.DP, 16, fpriv ) ) != 0 ||
       ( ret = mbedtls_mpi_write_file( "DQ = ", &rsa.DQ, 16, fpriv ) ) != 0 ||
       ( ret = mbedtls_mpi_write_file( "QP = ", &rsa.QP, 16, fpriv ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_mpi_write_file returned %d\n\n", ret );
        goto exit;
    }

    printf( " ok\n\n" );
    
exit:
    
    if( fpub  != NULL )
        fclose( fpub );
    
    if( fpriv != NULL )
        fclose( fpriv );
    
    mbedtls_rsa_free( &rsa );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    
#if defined(_WIN32)
    printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif
    
    return   ;
    
    
}