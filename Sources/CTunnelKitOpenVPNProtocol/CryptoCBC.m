//
//  CryptoCBC.m
//  TunnelKit
//
//  Created by Davide De Rosa on 7/6/18.
//  Copyright (c) 2024 Davide De Rosa. All rights reserved.
//
//  https://github.com/passepartoutvpn
//
//  This file is part of TunnelKit.
//
//  TunnelKit is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  TunnelKit is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with TunnelKit.  If not, see <http://www.gnu.org/licenses/>.
//
//  This file incorporates work covered by the following copyright and
//  permission notice:
//
//      Copyright (c) 2018-Present Private Internet Access
//
//      Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
//      The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
//      THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

#import <openssl/evp.h>
#import <openssl/rand.h>

#import "CryptoCBC.h"
#import "CryptoMacros.h"
#import "PacketMacros.h"
#import "ZeroingData.h"
#import "Allocation.h"
#import "Errors.h"

const NSInteger CryptoCBCMaxHMACLength = 100;

@interface CryptoCBC ()

@property (nonatomic, unsafe_unretained) const EVP_CIPHER *cipher;
@property (nonatomic, unsafe_unretained) const EVP_MD *digest;
@property (nonatomic, unsafe_unretained) const char *utfCipherName;
@property (nonatomic, unsafe_unretained) const char *utfDigestName;
@property (nonatomic, assign) int cipherKeyLength;
@property (nonatomic, assign) int cipherIVLength;
@property (nonatomic, assign) int hmacKeyLength;
@property (nonatomic, assign) int digestLength;

@property (nonatomic, unsafe_unretained) EVP_MAC *mac;
@property (nonatomic, unsafe_unretained) OSSL_PARAM *macParams;
@property (nonatomic, unsafe_unretained) EVP_CIPHER_CTX *cipherCtxEnc;
@property (nonatomic, unsafe_unretained) EVP_CIPHER_CTX *cipherCtxDec;
@property (nonatomic, strong) ZeroingData *hmacKeyEnc;
@property (nonatomic, strong) ZeroingData *hmacKeyDec;
@property (nonatomic, unsafe_unretained) uint8_t *bufferDecHMAC;

@end

@implementation CryptoCBC

- (instancetype)initWithCipherName:(NSString *)cipherName digestName:(NSString *)digestName
{
    NSParameterAssert(!cipherName || [[cipherName uppercaseString] hasSuffix:@"CBC"]);
    NSParameterAssert(digestName);

    self = [super init];
    if (self) {
        if (cipherName) {
            self.utfCipherName = calloc([cipherName length] + 1, sizeof(char));
            strncpy(self.utfCipherName, [cipherName UTF8String], [cipherName length]);
            self.cipher = EVP_get_cipherbyname(self.utfCipherName);
            NSAssert(self.cipher, @"Unknown cipher '%@'", cipherName);
        }
        self.utfDigestName = calloc([digestName length] + 1, sizeof(char));
        strncpy(self.utfDigestName, [digestName UTF8String], [digestName length]);
        self.digest = EVP_get_digestbyname(self.utfDigestName);
        NSAssert(self.digest, @"Unknown digest '%@'", digestName);

        if (cipherName) {
            self.cipherKeyLength = EVP_CIPHER_key_length(self.cipher);
            self.cipherIVLength = EVP_CIPHER_iv_length(self.cipher);
        }
        // as seen in OpenVPN's crypto_openssl.c:md_kt_size()
        self.hmacKeyLength = (int)EVP_MD_size(self.digest);
        self.digestLength = (int)EVP_MD_size(self.digest);

        if (cipherName) {
            self.cipherCtxEnc = EVP_CIPHER_CTX_new();
            self.cipherCtxDec = EVP_CIPHER_CTX_new();
        }

        self.mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
        OSSL_PARAM *macParams = calloc(2, sizeof(OSSL_PARAM));
        macParams[0] = OSSL_PARAM_construct_utf8_string("digest", self.utfDigestName, 0);
        macParams[1] = OSSL_PARAM_construct_end();
        self.macParams = macParams;

        self.bufferDecHMAC = allocate_safely(CryptoCBCMaxHMACLength);
    }
    return self;
}

- (void)dealloc
{
    if (self.cipher) {
        EVP_CIPHER_CTX_free(self.cipherCtxEnc);
        EVP_CIPHER_CTX_free(self.cipherCtxDec);
    }
    EVP_MAC_free(self.mac);
    free(self.macParams);
    bzero(self.bufferDecHMAC, CryptoCBCMaxHMACLength);
    free(self.bufferDecHMAC);

    if (self.utfCipherName) {
        free(self.utfCipherName);
    }
    free(self.utfDigestName);

    self.cipher = NULL;
    self.digest = NULL;
}

- (int)tagLength
{
    return 0;
}

- (NSInteger)encryptionCapacityWithLength:(NSInteger)length
{
    return safe_crypto_capacity(length, self.digestLength + self.cipherIVLength);
}

#pragma mark Encrypter

- (void)configureEncryptionWithCipherKey:(ZeroingData *)cipherKey hmacKey:(ZeroingData *)hmacKey
{
    NSParameterAssert(hmacKey);
    NSParameterAssert(hmacKey.count >= self.hmacKeyLength);

    if (self.cipher) {
        NSParameterAssert(cipherKey.count >= self.cipherKeyLength);

        EVP_CIPHER_CTX_reset(self.cipherCtxEnc);
        EVP_CipherInit(self.cipherCtxEnc, self.cipher, cipherKey.bytes, NULL, 1);
    }

    self.hmacKeyEnc = [[ZeroingData alloc] initWithBytes:hmacKey.bytes count:self.hmacKeyLength];
}

- (BOOL)encryptBytes:(const uint8_t *)bytes length:(NSInteger)length dest:(uint8_t *)dest destLength:(NSInteger *)destLength flags:(const CryptoFlags * _Nullable)flags error:(NSError * _Nullable __autoreleasing * _Nullable)error
{
    uint8_t *outIV = dest + self.digestLength;
    uint8_t *outEncrypted = dest + self.digestLength + self.cipherIVLength;
    int l1 = 0, l2 = 0;
    size_t l3 = 0;
    int code = 1;

    if (self.cipher) {
        if (!flags || !flags->forTesting) {
            if (RAND_bytes(outIV, self.cipherIVLength) != 1) {
                if (error) {
                    *error = OpenVPNErrorWithCode(OpenVPNErrorCodeCryptoRandomGenerator);
                }
                return NO;
            }
        }

        TUNNEL_CRYPTO_TRACK_STATUS(code) EVP_CipherInit(self.cipherCtxEnc, NULL, NULL, outIV, -1);
        TUNNEL_CRYPTO_TRACK_STATUS(code) EVP_CipherUpdate(self.cipherCtxEnc, outEncrypted, &l1, bytes, (int)length);
        TUNNEL_CRYPTO_TRACK_STATUS(code) EVP_CipherFinal_ex(self.cipherCtxEnc, outEncrypted + l1, &l2);
    }
    else {
        NSAssert(outEncrypted == outIV, @"cipherIVLength is non-zero");

        memcpy(outEncrypted, bytes, length);
        l1 = (int)length;
    }
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(self.mac);
    TUNNEL_CRYPTO_TRACK_STATUS(code) EVP_MAC_init(ctx, self.hmacKeyEnc.bytes, self.hmacKeyEnc.count, self.macParams);
    TUNNEL_CRYPTO_TRACK_STATUS(code) EVP_MAC_update(ctx, outIV, l1 + l2 + self.cipherIVLength);
    TUNNEL_CRYPTO_TRACK_STATUS(code) EVP_MAC_final(ctx, dest, &l3, self.digestLength);
    EVP_MAC_CTX_free(ctx);

    *destLength = l1 + l2 + self.cipherIVLength + self.digestLength;
    
    TUNNEL_CRYPTO_RETURN_STATUS(code)
}

- (id<DataPathEncrypter>)dataPathEncrypter
{
    return [[DataPathCryptoCBC alloc] initWithCrypto:self];
}

#pragma mark Decrypter

- (void)configureDecryptionWithCipherKey:(ZeroingData *)cipherKey hmacKey:(ZeroingData *)hmacKey
{
    NSParameterAssert(hmacKey);
    NSParameterAssert(hmacKey.count >= self.hmacKeyLength);

    if (self.cipher) {
        NSParameterAssert(cipherKey.count >= self.cipherKeyLength);

        EVP_CIPHER_CTX_reset(self.cipherCtxDec);
        EVP_CipherInit(self.cipherCtxDec, self.cipher, cipherKey.bytes, NULL, 0);
    }
    
    self.hmacKeyDec = [[ZeroingData alloc] initWithBytes:hmacKey.bytes count:self.hmacKeyLength];
}

- (BOOL)decryptBytes:(const uint8_t *)bytes length:(NSInteger)length dest:(uint8_t *)dest destLength:(NSInteger *)destLength flags:(const CryptoFlags * _Nullable)flags error:(NSError * _Nullable __autoreleasing * _Nullable)error
{
    const uint8_t *iv = bytes + self.digestLength;
    const uint8_t *encrypted = bytes + self.digestLength + self.cipherIVLength;
    size_t l1 = 0, l2 = 0;
    int code = 1;

    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(self.mac);
    TUNNEL_CRYPTO_TRACK_STATUS(code) EVP_MAC_init(ctx, self.hmacKeyDec.bytes, self.hmacKeyDec.count, self.macParams);
    TUNNEL_CRYPTO_TRACK_STATUS(code) EVP_MAC_update(ctx, bytes + self.digestLength, length - self.digestLength);
    TUNNEL_CRYPTO_TRACK_STATUS(code) EVP_MAC_final(ctx, self.bufferDecHMAC, &l1, self.digestLength);
    EVP_MAC_CTX_free(ctx);

    if (TUNNEL_CRYPTO_SUCCESS(code) && CRYPTO_memcmp(self.bufferDecHMAC, bytes, self.digestLength) != 0) {
        if (error) {
            *error = OpenVPNErrorWithCode(OpenVPNErrorCodeCryptoHMAC);
        }
        return NO;
    }
    
    if (self.cipher) {
        TUNNEL_CRYPTO_TRACK_STATUS(code) EVP_CipherInit(self.cipherCtxDec, NULL, NULL, iv, -1);
        TUNNEL_CRYPTO_TRACK_STATUS(code) EVP_CipherUpdate(self.cipherCtxDec, dest, (int *)&l1, encrypted, (int)length - self.digestLength - self.cipherIVLength);
        TUNNEL_CRYPTO_TRACK_STATUS(code) EVP_CipherFinal_ex(self.cipherCtxDec, dest + l1, (int *)&l2);

        *destLength = l1 + l2;
    } else {
        l2 = (int)length - l1;
        memcpy(dest, bytes + l1, l2);

        *destLength = l2;
    }

    TUNNEL_CRYPTO_RETURN_STATUS(code)
}

- (BOOL)verifyBytes:(const uint8_t *)bytes length:(NSInteger)length flags:(const CryptoFlags * _Nullable)flags error:(NSError * _Nullable __autoreleasing * _Nullable)error
{
    size_t l1 = 0;
    int code = 1;

    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(self.mac);
    TUNNEL_CRYPTO_TRACK_STATUS(code) EVP_MAC_init(ctx, self.hmacKeyDec.bytes, self.hmacKeyDec.count, self.macParams);
    TUNNEL_CRYPTO_TRACK_STATUS(code) EVP_MAC_update(ctx, bytes + self.digestLength, length - self.digestLength);
    TUNNEL_CRYPTO_TRACK_STATUS(code) EVP_MAC_final(ctx, self.bufferDecHMAC, &l1, self.digestLength);
    EVP_MAC_CTX_free(ctx);

    if (TUNNEL_CRYPTO_SUCCESS(code) && CRYPTO_memcmp(self.bufferDecHMAC, bytes, self.digestLength) != 0) {
        if (error) {
            *error = OpenVPNErrorWithCode(OpenVPNErrorCodeCryptoHMAC);
        }
        return NO;
    }

    TUNNEL_CRYPTO_RETURN_STATUS(code)
}

- (id<DataPathDecrypter>)dataPathDecrypter
{
    return [[DataPathCryptoCBC alloc] initWithCrypto:self];
}

@end

#pragma mark -

@interface DataPathCryptoCBC ()

@property (nonatomic, strong) CryptoCBC *crypto;

@end

@implementation DataPathCryptoCBC

- (instancetype)initWithCrypto:(CryptoCBC *)crypto
{
    if ((self = [super init])) {
        self.crypto = crypto;
        self.peerId = PacketPeerIdDisabled;
    }
    return self;
}

#pragma mark DataPathChannel

- (void)setPeerId:(uint32_t)peerId
{
    _peerId = peerId & 0xffffff;
}

- (NSInteger)encryptionCapacityWithLength:(NSInteger)length
{
    return [self.crypto encryptionCapacityWithLength:length];
}

#pragma mark DataPathEncrypter

- (void)assembleDataPacketWithBlock:(DataPathAssembleBlock)block packetId:(uint32_t)packetId payload:(NSData *)payload into:(uint8_t *)packetBytes length:(NSInteger *)packetLength
{
    uint8_t *ptr = packetBytes;
    *(uint32_t *)ptr = htonl(packetId);
    ptr += sizeof(uint32_t);
    *packetLength = (int)(ptr - packetBytes + payload.length);
    if (!block) {
        memcpy(ptr, payload.bytes, payload.length);
        return;
    }

    NSInteger packetLengthOffset;
    block(ptr, &packetLengthOffset, payload);
    *packetLength += packetLengthOffset;
}

- (NSData *)encryptedDataPacketWithKey:(uint8_t)key packetId:(uint32_t)packetId packetBytes:(const uint8_t *)packetBytes packetLength:(NSInteger)packetLength error:(NSError *__autoreleasing *)error
{
    DATA_PATH_ENCRYPT_INIT(self.peerId)

    const int capacity = headerLength + (int)[self.crypto encryptionCapacityWithLength:packetLength];
    NSMutableData *encryptedPacket = [[NSMutableData alloc] initWithLength:capacity];
    uint8_t *ptr = encryptedPacket.mutableBytes;
    NSInteger encryptedPacketLength = INT_MAX;
    const BOOL success = [self.crypto encryptBytes:packetBytes
                                            length:packetLength
                                              dest:(ptr + headerLength) // skip header bytes
                                        destLength:&encryptedPacketLength
                                             flags:NULL
                                             error:error];
    
    NSAssert(encryptedPacketLength <= capacity, @"Did not allocate enough bytes for payload");
    
    if (!success) {
        return nil;
    }

    if (hasPeerId) {
        PacketHeaderSetDataV2(ptr, key, self.peerId);
    }
    else {
        PacketHeaderSet(ptr, PacketCodeDataV1, key, nil);
    }
    encryptedPacket.length = headerLength + encryptedPacketLength;
    return encryptedPacket;
}

#pragma mark DataPathDecrypter

- (BOOL)decryptDataPacket:(NSData *)packet into:(uint8_t *)packetBytes length:(NSInteger *)packetLength packetId:(uint32_t *)packetId error:(NSError *__autoreleasing *)error
{
    NSAssert(packet.length > 0, @"Decrypting an empty packet, how did it get this far?");

    DATA_PATH_DECRYPT_INIT(packet)
    if (packet.length < headerLength + self.crypto.digestLength + self.crypto.cipherIVLength) {
        return NO;
    }

    // skip header = (code, key)
    const BOOL success = [self.crypto decryptBytes:(packet.bytes + headerLength)
                                            length:(int)(packet.length - headerLength)
                                              dest:packetBytes
                                        destLength:packetLength
                                             flags:NULL
                                             error:error];
    if (!success) {
        return NO;
    }
    if (hasPeerId) {
        if (peerId != self.peerId) {
            if (error) {
                *error = OpenVPNErrorWithCode(OpenVPNErrorCodeDataPathPeerIdMismatch);
            }
            return NO;
        }
    }
    *packetId = ntohl(*(uint32_t *)packetBytes);
    return YES;
}

- (NSData *)parsePayloadWithBlock:(DataPathParseBlock)block compressionHeader:(nonnull uint8_t *)compressionHeader packetBytes:(nonnull uint8_t *)packetBytes packetLength:(NSInteger)packetLength error:(NSError * _Nullable __autoreleasing * _Nullable)error
{
    uint8_t *payload = packetBytes;
    payload += sizeof(uint32_t); // packet id
    NSUInteger length = packetLength - (int)(payload - packetBytes);
    if (!block) {
        *compressionHeader = 0x00;
        return [NSData dataWithBytes:payload length:length];
    }

    NSInteger payloadOffset;
    NSInteger payloadHeaderLength;
    if (!block(payload, &payloadOffset, compressionHeader, &payloadHeaderLength, packetBytes, packetLength, error)) {
        return NULL;
    }
    length -= payloadHeaderLength;
    return [NSData dataWithBytes:(payload + payloadOffset) length:length];
}

@end
