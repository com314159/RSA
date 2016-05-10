/**
 * \file oid.c
 *
 * \brief Object Identifier (OID) database
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_OID_C)

#include "oid.h"
#include "rsa.h"

#include <stdio.h>
#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "platform.h"
#else
#define mbedtls_snprintf snprintf
#endif

#if defined(MBEDTLS_X509_USE_C) || defined(MBEDTLS_X509_CREATE_C)
#include "mbedtls/x509.h"
#endif

/*
 * Macro to automatically add the size of #define'd OIDs
 */
#define ADD_LEN(s)      s, MBEDTLS_OID_SIZE(s)

/*
 * Macro to generate an internal function for oid_XXX_from_asn1() (used by
 * the other functions)
 */
#define FN_OID_TYPED_FROM_ASN1( TYPE_T, NAME, LIST )                        \
static const TYPE_T * oid_ ## NAME ## _from_asn1( const mbedtls_asn1_buf *oid )     \
{                                                                           \
    const TYPE_T *p = LIST;                                                 \
    const mbedtls_oid_descriptor_t *cur = (const mbedtls_oid_descriptor_t *) p;             \
    if( p == NULL || oid == NULL ) return( NULL );                          \
    while( cur->asn1 != NULL ) {                                            \
        if( cur->asn1_len == oid->len &&                                    \
            memcmp( cur->asn1, oid->p, oid->len ) == 0 ) {                  \
            return( p );                                                    \
        }                                                                   \
        p++;                                                                \
        cur = (const mbedtls_oid_descriptor_t *) p;                                 \
    }                                                                       \
    return( NULL );                                                         \
}

/*
 * Macro to generate a function for retrieving a single attribute from the
 * descriptor of an mbedtls_oid_descriptor_t wrapper.
 */
#define FN_OID_GET_DESCRIPTOR_ATTR1(FN_NAME, TYPE_T, TYPE_NAME, ATTR1_TYPE, ATTR1) \
int FN_NAME( const mbedtls_asn1_buf *oid, ATTR1_TYPE * ATTR1 )                  \
{                                                                       \
    const TYPE_T *data = oid_ ## TYPE_NAME ## _from_asn1( oid );        \
    if( data == NULL ) return( MBEDTLS_ERR_OID_NOT_FOUND );            \
    *ATTR1 = data->descriptor.ATTR1;                                    \
    return( 0 );                                                        \
}

/*
 * Macro to generate a function for retrieving a single attribute from an
 * mbedtls_oid_descriptor_t wrapper.
 */
#define FN_OID_GET_ATTR1(FN_NAME, TYPE_T, TYPE_NAME, ATTR1_TYPE, ATTR1) \
int FN_NAME( const mbedtls_asn1_buf *oid, ATTR1_TYPE * ATTR1 )                  \
{                                                                       \
    const TYPE_T *data = oid_ ## TYPE_NAME ## _from_asn1( oid );        \
    if( data == NULL ) return( MBEDTLS_ERR_OID_NOT_FOUND );            \
    *ATTR1 = data->ATTR1;                                               \
    return( 0 );                                                        \
}

/*
 * Macro to generate a function for retrieving two attributes from an
 * mbedtls_oid_descriptor_t wrapper.
 */
#define FN_OID_GET_ATTR2(FN_NAME, TYPE_T, TYPE_NAME, ATTR1_TYPE, ATTR1,     \
                         ATTR2_TYPE, ATTR2)                                 \
int FN_NAME( const mbedtls_asn1_buf *oid, ATTR1_TYPE * ATTR1, ATTR2_TYPE * ATTR2 )  \
{                                                                           \
    const TYPE_T *data = oid_ ## TYPE_NAME ## _from_asn1( oid );            \
    if( data == NULL ) return( MBEDTLS_ERR_OID_NOT_FOUND );                \
    *ATTR1 = data->ATTR1;                                                   \
    *ATTR2 = data->ATTR2;                                                   \
    return( 0 );                                                            \
}

/*
 * Macro to generate a function for retrieving the OID based on a single
 * attribute from a mbedtls_oid_descriptor_t wrapper.
 */
#define FN_OID_GET_OID_BY_ATTR1(FN_NAME, TYPE_T, LIST, ATTR1_TYPE, ATTR1)   \
int FN_NAME( ATTR1_TYPE ATTR1, const char **oid, size_t *olen )             \
{                                                                           \
    const TYPE_T *cur = LIST;                                               \
    while( cur->descriptor.asn1 != NULL ) {                                 \
        if( cur->ATTR1 == ATTR1 ) {                                         \
            *oid = cur->descriptor.asn1;                                    \
            *olen = cur->descriptor.asn1_len;                               \
            return( 0 );                                                    \
        }                                                                   \
        cur++;                                                              \
    }                                                                       \
    return( MBEDTLS_ERR_OID_NOT_FOUND );                                   \
}

/*
 * Macro to generate a function for retrieving the OID based on two
 * attributes from a mbedtls_oid_descriptor_t wrapper.
 */
#define FN_OID_GET_OID_BY_ATTR2(FN_NAME, TYPE_T, LIST, ATTR1_TYPE, ATTR1,   \
                                ATTR2_TYPE, ATTR2)                          \
int FN_NAME( ATTR1_TYPE ATTR1, ATTR2_TYPE ATTR2, const char **oid ,         \
             size_t *olen )                                                 \
{                                                                           \
    const TYPE_T *cur = LIST;                                               \
    while( cur->descriptor.asn1 != NULL ) {                                 \
        if( cur->ATTR1 == ATTR1 && cur->ATTR2 == ATTR2 ) {                  \
            *oid = cur->descriptor.asn1;                                    \
            *olen = cur->descriptor.asn1_len;                               \
            return( 0 );                                                    \
        }                                                                   \
        cur++;                                                              \
    }                                                                       \
    return( MBEDTLS_ERR_OID_NOT_FOUND );                                   \
}

/*
 * For X520 attribute types
 */
typedef struct {
    mbedtls_oid_descriptor_t    descriptor;
    const char          *short_name;
} oid_x520_attr_t;

static const oid_x520_attr_t oid_x520_attr_type[] =
{
    {
        { ADD_LEN( MBEDTLS_OID_AT_CN ),          "id-at-commonName",               "Common Name" },
        "CN",
    },
    {
        { ADD_LEN( MBEDTLS_OID_AT_COUNTRY ),     "id-at-countryName",              "Country" },
        "C",
    },
    {
        { ADD_LEN( MBEDTLS_OID_AT_LOCALITY ),    "id-at-locality",                 "Locality" },
        "L",
    },
    {
        { ADD_LEN( MBEDTLS_OID_AT_STATE ),       "id-at-state",                    "State" },
        "ST",
    },
    {
        { ADD_LEN( MBEDTLS_OID_AT_ORGANIZATION ),"id-at-organizationName",         "Organization" },
        "O",
    },
    {
        { ADD_LEN( MBEDTLS_OID_AT_ORG_UNIT ),    "id-at-organizationalUnitName",   "Org Unit" },
        "OU",
    },
    {
        { ADD_LEN( MBEDTLS_OID_PKCS9_EMAIL ),    "emailAddress",                   "E-mail address" },
        "emailAddress",
    },
    {
        { ADD_LEN( MBEDTLS_OID_AT_SERIAL_NUMBER ),"id-at-serialNumber",            "Serial number" },
        "serialNumber",
    },
    {
        { ADD_LEN( MBEDTLS_OID_AT_POSTAL_ADDRESS ),"id-at-postalAddress",          "Postal address" },
        "postalAddress",
    },
    {
        { ADD_LEN( MBEDTLS_OID_AT_POSTAL_CODE ), "id-at-postalCode",               "Postal code" },
        "postalCode",
    },
    {
        { ADD_LEN( MBEDTLS_OID_AT_SUR_NAME ),    "id-at-surName",                  "Surname" },
        "SN",
    },
    {
        { ADD_LEN( MBEDTLS_OID_AT_GIVEN_NAME ),  "id-at-givenName",                "Given name" },
        "GN",
    },
    {
        { ADD_LEN( MBEDTLS_OID_AT_INITIALS ),    "id-at-initials",                 "Initials" },
        "initials",
    },
    {
        { ADD_LEN( MBEDTLS_OID_AT_GENERATION_QUALIFIER ), "id-at-generationQualifier", "Generation qualifier" },
        "generationQualifier",
    },
    {
        { ADD_LEN( MBEDTLS_OID_AT_TITLE ),       "id-at-title",                    "Title" },
        "title",
    },
    {
        { ADD_LEN( MBEDTLS_OID_AT_DN_QUALIFIER ),"id-at-dnQualifier",              "Distinguished Name qualifier" },
        "dnQualifier",
    },
    {
        { ADD_LEN( MBEDTLS_OID_AT_PSEUDONYM ),   "id-at-pseudonym",                "Pseudonym" },
        "pseudonym",
    },
    {
        { ADD_LEN( MBEDTLS_OID_DOMAIN_COMPONENT ), "id-domainComponent",           "Domain component" },
        "DC",
    },
    {
        { ADD_LEN( MBEDTLS_OID_AT_UNIQUE_IDENTIFIER ), "id-at-uniqueIdentifier",    "Unique Identifier" },
        "uniqueIdentifier",
    },
    {
        { NULL, 0, NULL, NULL },
        NULL,
    }
};

FN_OID_TYPED_FROM_ASN1(oid_x520_attr_t, x520_attr, oid_x520_attr_type)
FN_OID_GET_ATTR1(mbedtls_oid_get_attr_short_name, oid_x520_attr_t, x520_attr, const char *, short_name)

#if defined(MBEDTLS_X509_USE_C) || defined(MBEDTLS_X509_CREATE_C)
/*
 * For X509 extensions
 */
typedef struct {
    mbedtls_oid_descriptor_t    descriptor;
    int                 ext_type;
} oid_x509_ext_t;

static const oid_x509_ext_t oid_x509_ext[] =
{
    {
        { ADD_LEN( MBEDTLS_OID_BASIC_CONSTRAINTS ),    "id-ce-basicConstraints",   "Basic Constraints" },
        MBEDTLS_X509_EXT_BASIC_CONSTRAINTS,
    },
    {
        { ADD_LEN( MBEDTLS_OID_KEY_USAGE ),            "id-ce-keyUsage",           "Key Usage" },
        MBEDTLS_X509_EXT_KEY_USAGE,
    },
    {
        { ADD_LEN( MBEDTLS_OID_EXTENDED_KEY_USAGE ),   "id-ce-extKeyUsage",        "Extended Key Usage" },
        MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE,
    },
    {
        { ADD_LEN( MBEDTLS_OID_SUBJECT_ALT_NAME ),     "id-ce-subjectAltName",     "Subject Alt Name" },
        MBEDTLS_X509_EXT_SUBJECT_ALT_NAME,
    },
    {
        { ADD_LEN( MBEDTLS_OID_NS_CERT_TYPE ),         "id-netscape-certtype",     "Netscape Certificate Type" },
        MBEDTLS_X509_EXT_NS_CERT_TYPE,
    },
    {
        { NULL, 0, NULL, NULL },
        0,
    },
};

FN_OID_TYPED_FROM_ASN1(oid_x509_ext_t, x509_ext, oid_x509_ext)
FN_OID_GET_ATTR1(mbedtls_oid_get_x509_ext_type, oid_x509_ext_t, x509_ext, int, ext_type)

static const mbedtls_oid_descriptor_t oid_ext_key_usage[] =
{
    { ADD_LEN( MBEDTLS_OID_SERVER_AUTH ),      "id-kp-serverAuth",      "TLS Web Server Authentication" },
    { ADD_LEN( MBEDTLS_OID_CLIENT_AUTH ),      "id-kp-clientAuth",      "TLS Web Client Authentication" },
    { ADD_LEN( MBEDTLS_OID_CODE_SIGNING ),     "id-kp-codeSigning",     "Code Signing" },
    { ADD_LEN( MBEDTLS_OID_EMAIL_PROTECTION ), "id-kp-emailProtection", "E-mail Protection" },
    { ADD_LEN( MBEDTLS_OID_TIME_STAMPING ),    "id-kp-timeStamping",    "Time Stamping" },
    { ADD_LEN( MBEDTLS_OID_OCSP_SIGNING ),     "id-kp-OCSPSigning",     "OCSP Signing" },
    { NULL, 0, NULL, NULL },
};

FN_OID_TYPED_FROM_ASN1(mbedtls_oid_descriptor_t, ext_key_usage, oid_ext_key_usage)
FN_OID_GET_ATTR1(mbedtls_oid_get_extended_key_usage, mbedtls_oid_descriptor_t, ext_key_usage, const char *, description)
#endif /* MBEDTLS_X509_USE_C || MBEDTLS_X509_CREATE_C */


#if defined(MBEDTLS_CIPHER_C)
/*
 * For PKCS#5 PBES2 encryption algorithm
 */
typedef struct {
    mbedtls_oid_descriptor_t    descriptor;
    mbedtls_cipher_type_t       cipher_alg;
} oid_cipher_alg_t;

static const oid_cipher_alg_t oid_cipher_alg[] =
{
    {
        { ADD_LEN( MBEDTLS_OID_DES_CBC ),              "desCBC",       "DES-CBC" },
        MBEDTLS_CIPHER_DES_CBC,
    },
    {
        { ADD_LEN( MBEDTLS_OID_DES_EDE3_CBC ),         "des-ede3-cbc", "DES-EDE3-CBC" },
        MBEDTLS_CIPHER_DES_EDE3_CBC,
    },
    {
        { NULL, 0, NULL, NULL },
        MBEDTLS_CIPHER_NONE,
    },
};

FN_OID_TYPED_FROM_ASN1(oid_cipher_alg_t, cipher_alg, oid_cipher_alg)
FN_OID_GET_ATTR1(mbedtls_oid_get_cipher_alg, oid_cipher_alg_t, cipher_alg, mbedtls_cipher_type_t, cipher_alg)
#endif /* MBEDTLS_CIPHER_C */

#if defined(MBEDTLS_MD_C)
/*
 * For digestAlgorithm
 */
typedef struct {
    mbedtls_oid_descriptor_t    descriptor;
    mbedtls_md_type_t           md_alg;
} oid_md_alg_t;

static const oid_md_alg_t oid_md_alg[] =
{
    {
        { ADD_LEN( MBEDTLS_OID_DIGEST_ALG_MD2 ),       "id-md2",       "MD2" },
        MBEDTLS_MD_MD2,
    },
    {
        { ADD_LEN( MBEDTLS_OID_DIGEST_ALG_MD4 ),       "id-md4",       "MD4" },
        MBEDTLS_MD_MD4,
    },
    {
        { ADD_LEN( MBEDTLS_OID_DIGEST_ALG_MD5 ),       "id-md5",       "MD5" },
        MBEDTLS_MD_MD5,
    },
    {
        { ADD_LEN( MBEDTLS_OID_DIGEST_ALG_SHA1 ),      "id-sha1",      "SHA-1" },
        MBEDTLS_MD_SHA1,
    },
    {
        { ADD_LEN( MBEDTLS_OID_DIGEST_ALG_SHA224 ),    "id-sha224",    "SHA-224" },
        MBEDTLS_MD_SHA224,
    },
    {
        { ADD_LEN( MBEDTLS_OID_DIGEST_ALG_SHA256 ),    "id-sha256",    "SHA-256" },
        MBEDTLS_MD_SHA256,
    },
    {
        { ADD_LEN( MBEDTLS_OID_DIGEST_ALG_SHA384 ),    "id-sha384",    "SHA-384" },
        MBEDTLS_MD_SHA384,
    },
    {
        { ADD_LEN( MBEDTLS_OID_DIGEST_ALG_SHA512 ),    "id-sha512",    "SHA-512" },
        MBEDTLS_MD_SHA512,
    },
    {
        { NULL, 0, NULL, NULL },
        MBEDTLS_MD_NONE,
    },
};

FN_OID_TYPED_FROM_ASN1(oid_md_alg_t, md_alg, oid_md_alg)
FN_OID_GET_ATTR1(mbedtls_oid_get_md_alg, oid_md_alg_t, md_alg, mbedtls_md_type_t, md_alg)
FN_OID_GET_OID_BY_ATTR1(mbedtls_oid_get_oid_by_md, oid_md_alg_t, oid_md_alg, mbedtls_md_type_t, md_alg)
#endif /* MBEDTLS_MD_C */

#if defined(MBEDTLS_PKCS12_C)

#endif /* MBEDTLS_PKCS12_C */

#define OID_SAFE_SNPRINTF                               \
    do {                                                \
        if( ret < 0 || (size_t) ret >= n )              \
            return( MBEDTLS_ERR_OID_BUF_TOO_SMALL );    \
                                                        \
        n -= (size_t) ret;                              \
        p += (size_t) ret;                              \
    } while( 0 )

/* Return the x.y.z.... style numeric string for the given OID */
int mbedtls_oid_get_numeric_string( char *buf, size_t size,
                            const mbedtls_asn1_buf *oid )
{
    int ret;
    size_t i, n;
    unsigned int value;
    char *p;

    p = buf;
    n = size;

    /* First byte contains first two dots */
    if( oid->len > 0 )
    {
        ret = mbedtls_snprintf( p, n, "%d.%d", oid->p[0] / 40, oid->p[0] % 40 );
        OID_SAFE_SNPRINTF;
    }

    value = 0;
    for( i = 1; i < oid->len; i++ )
    {
        /* Prevent overflow in value. */
        if( ( ( value << 7 ) >> 7 ) != value )
            return( MBEDTLS_ERR_OID_BUF_TOO_SMALL );

        value <<= 7;
        value += oid->p[i] & 0x7F;

        if( !( oid->p[i] & 0x80 ) )
        {
            /* Last byte */
            ret = mbedtls_snprintf( p, n, ".%d", value );
            OID_SAFE_SNPRINTF;
            value = 0;
        }
    }

    return( (int) ( size - n ) );
}

#endif /* MBEDTLS_OID_C */
