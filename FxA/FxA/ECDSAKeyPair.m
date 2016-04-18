// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/


#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "NSData+Utils.h"
#include "NSData+SHA.h"
#include "CHNumber.h"

#import "ASNUtils.h"
#import "ECDSAKeyPair.h"

#define NID_P256 NID_X9_62_prime256v1

const char* kECDSAP256Algorithm = "ECDSA-P256";

#define kECDSAFieldBytes 32

@implementation ECDSAPoint
@end

@implementation ECDSAPrivateKey {
    EC_KEY *_ecdsa;
}

- (id) initWithJSONRepresentation: (NSDictionary*) object
{
    CHNumber *d = [CHNumber numberWithString: object[@"d"]];
    CHNumber *x = [CHNumber numberWithString: object[@"x"]];
    CHNumber *y = [CHNumber numberWithString: object[@"y"]];
    if (d == nil || x == nil || y == nil) {
        return nil;
    }

    ECDSAPoint *pt = [ECDSAPoint new];
    pt.x = x;
    pt.y = y;

    return [self initWithPrivateKey: d point: pt group: ECDSAGroupP256];
}

- (instancetype) initWithBinaryRepresentation: (NSData*) data group: (ECDSAGroup) group;
{
    if (group != ECDSAGroupP256) {
        return self;
    }

    if ((self = [super init]) != nil) {
        _ecdsa = EC_KEY_new_by_curve_name(NID_P256);

        EC_GROUP *ecgroup = EC_KEY_get0_group(_ecdsa);
        EC_POINT *pub = EC_KEY_get0_public_key(_ecdsa);
        BIGNUM *priv = EC_KEY_get0_private_key(_ecdsa);

        EC_POINT_oct2point(ecgroup, pub, [data bytes], [data length], NULL);
        EC_KEY_set_public_key(_ecdsa, pub);

        size_t pubLen = EC_POINT_point2oct(ecgroup, pub, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
        if (pubLen < [data length]) {
            BN_bin2bn([data bytes] + pubLen, [data length] - pubLen, priv);
        }
    }
    return self;
}

- (instancetype) initWithPrivateKey: (CHNumber*) d point: (ECDSAPoint*) p group: (ECDSAGroup) group;
{
    if ((self = [super init]) != nil) {
        _ecdsa = EC_KEY_new_by_curve_name(NID_P256);
        EC_KEY_set_public_key_affine_coordinates(_ecdsa, [p.x bigNumValue], [p.y bigNumValue]);
        EC_KEY_set_private_key(_ecdsa, [d bigNumValue]);
    }
    return self;
}

- (void) dealloc
{
    if (_ecdsa != NULL) {
        EC_KEY_free(_ecdsa);
        _ecdsa = NULL;
    }
}

- (NSDictionary*) JSONRepresentation
{
    EC_GROUP *ecgroup = EC_KEY_get0_group(_ecdsa);
    BIGNUM *d = EC_KEY_get0_private_key(_ecdsa);
    EC_POINT *pub = EC_KEY_get0_public_key(_ecdsa);

    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    if (!EC_POINT_get_affine_coordinates_GFp(ecgroup, pub, x, y, NULL)) {
        BN_free(x);
        BN_free(y);
        return nil;
    }


    NSDictionary *ret = @{
                          @"algorithm": @"ES",
                          @"d": [[CHNumber numberWithOpenSSLNumber: d] stringValue],
                          @"x": [[CHNumber numberWithOpenSSLNumber: x] stringValue],
                          @"y": [[CHNumber numberWithOpenSSLNumber: y] stringValue]
                          };

    BN_free(x);
    BN_free(y);
    return ret;
}

- (NSData*) BinaryRepresentation
{
    EC_GROUP *ecgroup = EC_KEY_get0_group(_ecdsa);

    BIGNUM *d = EC_KEY_get0_private_key(_ecdsa);
    NSMutableData *priv = [[NSMutableData alloc] initWithCapacity: BN_num_bytes(d)];

    EC_POINT *pub = EC_KEY_get0_public_key(_ecdsa);
    size_t ptLen = EC_POINT_point2oct(ecgroup, pub, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    NSMutableData *buf = [[NSMutableData alloc] initWithLength: ptLen];
    EC_POINT_point2oct(ecgroup, pub, POINT_CONVERSION_UNCOMPRESSED, [buf bytes], ptLen, NULL);

    [buf appendData: priv];
    return buf;
}

- (NSString*) algorithm
{
    return [[NSString alloc] initWithUTF8String:kECDSAP256Algorithm];
}

- (NSData*) signMessageString: (NSString*) string encoding: (NSStringEncoding) encoding
{
    return [self signMessage: [string dataUsingEncoding: encoding]];
}

- (NSData*) signMessage: (NSData*) message
{
    NSData *signature = nil;
    
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey != NULL) {
        if (EVP_PKEY_set1_EC_KEY(pkey, _ecdsa)) {
            EVP_MD_CTX *ctx = EVP_MD_CTX_create();
            if (ctx != NULL) {
                if (EVP_SignInit_ex(ctx, EVP_sha256(), NULL)) {
                    if (EVP_SignUpdate(ctx, [message bytes], [message length])) {
                        unsigned int sig_size;
                        unsigned char *sig_data = malloc(EVP_PKEY_size(pkey));
                        if (sig_data != NULL) {
                            if (EVP_SignFinal(ctx, sig_data, &sig_size, pkey)) {
                                signature = [NSData dataWithBytesNoCopy: sig_data length: sig_size freeWhenDone: YES];
                            }
                        }
                    }
                }
                EVP_MD_CTX_destroy(ctx);
            }
        }
        EVP_PKEY_free(pkey);
    }
    
    return signature;
}

- (NSData*) selfSignedCertificateWithName: (NSString*) name slack: (int) slack lifetime: (int) lifetime
{
    X509* x509 = X509_new();
    if (!x509) {
        return nil;
    }

    /* Set the serial number. */
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    X509_gmtime_adj(X509_get_notBefore(x509), -1 * slack);
    X509_gmtime_adj(X509_get_notAfter(x509), lifetime);

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        return nil;
    }
    if (!EVP_PKEY_set1_EC_KEY(pkey, _ecdsa)) {
        EVP_PKEY_free(pkey);
        return nil;
    }
    X509_set_pubkey(x509, pkey);

    X509_NAME* subject = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, (unsigned char *)[name cStringUsingEncoding:NSUTF8StringEncoding], -1, -1, 0);
    X509_set_issuer_name(x509, subject);

    if(!X509_sign(x509, pkey, EVP_sha256()))
    {
        EVP_PKEY_free(pkey);
        X509_free(x509);
        return NULL;
    }

    unsigned char* der = NULL;
    int len = i2d_X509(x509, &der);
    if (len == 0){
        EVP_PKEY_free(pkey);
        X509_free(x509);
        return NULL;
    }

    return [[NSData alloc] initWithBytesNoCopy:der length:len];
}

@end


@implementation ECDSAPublicKey {
    EC_KEY *_ecdsa;
}

- (id) initWithJSONRepresentation: (NSDictionary*) object
{
    CHNumber *x = [CHNumber numberWithString: object[@"x"]];
    CHNumber *y = [CHNumber numberWithString: object[@"y"]];
    if (x == nil || y == nil) {
        return nil;
    }

    ECDSAPoint *pt = [ECDSAPoint new];
    pt.x = x;
    pt.y = y;

    return [self initWithPublicKey: pt group: ECDSAGroupP256];
}

- (instancetype) initWithPublicKey: (ECDSAPoint*) p group: (ECDSAGroup) group;
{
    if (group != ECDSAGroupP256) {
        return self;
    }
    
    if ((self = [super init]) != nil) {
        _ecdsa = EC_KEY_new_by_curve_name(NID_P256);
        EC_KEY_set_public_key_affine_coordinates(_ecdsa, [p.x bigNumValue], [p.y bigNumValue]);
    }
    return self;
}

- (instancetype) initWithBinaryRepresentation: (NSData*) data group: (ECDSAGroup) group;
{
    if (group != ECDSAGroupP256) {
        return self;
    }

    if ((self = [super init]) != nil) {
        _ecdsa = EC_KEY_new_by_curve_name(NID_P256);

        EC_GROUP *ecgroup = EC_KEY_get0_group(_ecdsa);
        EC_POINT *pub = EC_KEY_get0_public_key(_ecdsa);

        EC_POINT_oct2point(ecgroup, pub, [data bytes], [data length], NULL);
    }
    return self;
}

- (void) dealloc
{
    if (_ecdsa != NULL) {
        EC_KEY_free(_ecdsa);
        _ecdsa = NULL;
    }
}

- (NSDictionary*) JSONRepresentation
{
    EC_GROUP *ecgroup = EC_KEY_get0_group(_ecdsa);
    EC_POINT *pub = EC_KEY_get0_public_key(_ecdsa);

    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    if (!EC_POINT_get_affine_coordinates_GFp(ecgroup, pub, x, y, NULL)) {
        BN_free(x);
        BN_free(y);
        return nil;
    }

    return @{
             @"algorithm": @"ES",
             @"x": [[CHNumber numberWithOpenSSLNumber: x] stringValue],
             @"y": [[CHNumber numberWithOpenSSLNumber: y] stringValue]
             };
}

- (NSData*) BinaryRepresentation
{
    // size_t EC_POINT_point2oct(const EC_GROUP *group, const EC_POINT *p,
    //                           point_conversion_form_t form,
    //                           unsigned char *buf, size_t len, BN_CTX *ctx);
    EC_GROUP *ecgroup = EC_KEY_get0_group(_ecdsa);
    EC_POINT *pub = EC_KEY_get0_public_key(_ecdsa);

    size_t ptLen = EC_POINT_point2oct(ecgroup, pub, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);

    NSData *mut = [[NSMutableData alloc] initWithLength: ptLen];
    EC_POINT_point2oct(ecgroup, pub, POINT_CONVERSION_UNCOMPRESSED, [mut bytes], ptLen, NULL);
    return mut;
}

- (NSString*) algorithm
{
    return [[NSString alloc] initWithUTF8String:kECDSAP256Algorithm];
}

- (BOOL) verifySignature: (NSData*) signature againstMessage: (NSData*) message
{
    BOOL verified = NO;
    
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey != NULL) {
        if (EVP_PKEY_set1_EC_KEY(pkey, _ecdsa) == 1) {
            EVP_MD_CTX *ctx = EVP_MD_CTX_create();
            if (ctx != NULL) {
                if (EVP_VerifyInit_ex(ctx, EVP_sha256(), NULL) == 1) {
                    if (EVP_VerifyUpdate(ctx, [message bytes], [message length]) ==  1) {
                        int err = EVP_VerifyFinal(ctx, [signature bytes], [signature length], pkey);
                        if (err == 1) {
                            verified = YES;
                        } else if (err == -1) {
                            unsigned long e = ERR_get_error();
                            
                            char buf[120];
                            ERR_error_string(e, buf);
                            NSLog(@"Error: %s", buf);
                        }
                    }
                }
                EVP_MD_CTX_destroy(ctx);
            }
        }
        EVP_PKEY_free(pkey);
    }
    
    return verified;
}

- (BOOL) verifySignature: (NSData*) signature againstMessageString: (NSString*) message encoding: (NSStringEncoding) encoding
{
    return [self verifySignature: signature againstMessage: [message dataUsingEncoding: encoding]];
}

@end


@implementation ECDSAKeyPair

+ (instancetype) generateKeyPairForGroup: (ECDSAGroup) group
{
    if (group != ECDSAGroupP256) {
        return nil;
    }
    
    EC_KEY *ecdsa = EC_KEY_new_by_curve_name(NID_P256);
    if (ecdsa == NULL) {
        return nil;
    }
    
    EC_GROUP *ecgroup = EC_KEY_get0_group(ecdsa);
    
    if (EC_KEY_generate_key(ecdsa) == 0) {
        EC_KEY_free(ecdsa);
        return nil;
    }
    
    // These return references to the internal fields, so we don't have to free them
    BIGNUM *priv = EC_KEY_get0_private_key(ecdsa);
    EC_POINT *pub = EC_KEY_get0_public_key(ecdsa);
    
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    if (!EC_POINT_get_affine_coordinates_GFp(ecgroup, pub, x, y, NULL)) {
        BN_free(x);
        BN_free(y);
        EC_KEY_free(ecdsa);
        return nil;
    }
    
    ECDSAPoint *pt = [ECDSAPoint new];
    pt.x = [CHNumber numberWithOpenSSLNumber: x];
    pt.y = [CHNumber numberWithOpenSSLNumber: y];
    
    CHNumber *d = [CHNumber numberWithOpenSSLNumber: priv];
    
    ECDSAPrivateKey *privateKey = [[ECDSAPrivateKey alloc] initWithPrivateKey: d point: pt group: group];
    ECDSAPublicKey *publicKey = [[ECDSAPublicKey alloc] initWithPublicKey: pt group: group];
    
    BN_free(x);
    BN_free(y);
    EC_KEY_free(ecdsa);
    
    return [[self alloc] initWithPublicKey: publicKey privateKey: privateKey];
}

@end
