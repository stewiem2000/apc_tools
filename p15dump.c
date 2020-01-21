/*
 * unfinished work!
 * This was supposed to dump the private key of an apc certificate (strip the header first) but (using cryptlib version 3.4.1) opening the key already failed.
 *
 * Use, modification, and distribution of pemtrans is allowed without
 * any limitations. There is no warranty, express or implied.
 */


#include <cryptlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>


void check( int n, CRYPT_HANDLE c, char *s )
{
    int status;
    int locus = 0;
    int type = 0;
    int length = 0;

    if ( n == CRYPT_OK )
        return;

    fprintf( stderr, "%s failed.\n", s );
    fprintf( stderr, "\tError code: %d\n", n );

    status = cryptGetAttribute( c, CRYPT_ATTRIBUTE_ERRORLOCUS, &locus );
    if ( cryptStatusOK( status ) && locus != 0 )
        fprintf( stderr, "\tError locus: %d\n", locus );

    status = cryptGetAttribute( c, CRYPT_ATTRIBUTE_ERRORTYPE, &type );
    if ( cryptStatusOK( status ) && type != 0 )
        fprintf( stderr, "\tError type: %d\n", type );

    status = cryptGetAttributeString( c, CRYPT_ATTRIBUTE_ERRORMESSAGE,
                                      0, &length );
    if ( cryptStatusOK( status ) ) {
        char * err = malloc( length );
        if ( !err )
            exit( -1 );
        status = cryptGetAttributeString( c, CRYPT_ATTRIBUTE_ERRORMESSAGE,
                                          err, &length );
        if ( cryptStatusOK( status ) )
            fprintf( stderr, "\tError message: %s\n", err );
    }

    exit( -1 );
}


int main( int argc, char *argv[] )
{
    int n;
    FILE *f;
    char *buf[8];
    char *outFile;
    char *p15File;
    char *certFile;
    char *certData;
    char *label;
    char *secret;
    struct stat st;
    int usage;

    CRYPT_KEYSET keyset;
    CRYPT_CONTEXT pKey;
    CRYPT_PKCINFO_RSA rsa;
    CRYPT_CERTIFICATE cert;
    CRYPT_KEYOPT_TYPE opt;

    label = "Private key";
    secret = "user";
    p15File = "server.p15";


    if ( argc != 4 ) {
        fprintf( stderr,
                 "Syntax: %s <key> <label> <secret>\n",
                 argv[0] );
        exit( -1 );
    }

    p15File = argv[1];
    label = argv[2];
    secret = argv[3];

    if ( cryptInit() != CRYPT_OK ) {
        fprintf( stderr, "Couldn't initialize cryptLib\n" );
        exit( -1 );
    }

    /* Read the key from the keyset using the password */
    n = cryptKeysetOpen( &keyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE, p15File, CRYPT_KEYOPT_NONE );
    check( n, keyset, "cryptKeysetOpen" );
    n = cryptGetPrivateKey( keyset, &pKey, CRYPT_KEYID_NAME, label, secret );
    check( n, keyset, "GetPrivateKey" );

    cryptKeysetClose( keyset );
    cryptDestroyContext( pKey );
    //cryptDestroyCert( cert );
    exit( 0 );
}
