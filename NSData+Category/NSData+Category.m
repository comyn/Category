//
//  NSData+AES128.m
//  AESSecret
//
//  Created by comyn on 2018/3/14.
//  Copyright © 2018年 comyn. All rights reserved.
//

#import "NSData+Category.h"
#import <CommonCrypto/CommonCryptor.h>

@implementation NSData (Category)

@end

@implementation NSData (HexString)

#pragma mark - hex string转换为NSData

+ (instancetype)dataWithHexStr:(NSString*)str {
    if (!str || [str length] ==0) {
        return nil;
    }
    
    NSMutableData *hexData = [[NSMutableData alloc]initWithCapacity:[str length]*2];
    NSRange range;
    if ([str length] %2==0) {
        range = NSMakeRange(0,2);
    } else {
        range = NSMakeRange(0,1);
    }
    for (NSInteger i = range.location; i < [str length]; i +=2) {
        unsigned int anInt;
        NSString *hexCharStr = [str substringWithRange:range];
        NSScanner *scanner = [[NSScanner alloc]initWithString:hexCharStr];
        
        [scanner scanHexInt:&anInt];
        NSData *entity = [[NSData alloc]initWithBytes:&anInt length:1];
        [hexData appendData:entity];
        
        range.location+= range.length;
        range.length=2;
    }
    //    NSLog(@"hexdata: %@", hexData);
    return hexData;
}

#pragma mark - NSData转换为hex string
- (NSString*)dataToHexStr {
    if (!self || [self length] ==0) {
        return @"";
    }
    NSMutableString *string = [[NSMutableString alloc]initWithCapacity:[self length]/2];
    
    [self enumerateByteRangesUsingBlock:^(const void*bytes,NSRange byteRange,BOOL*stop) {
        unsigned char *dataBytes = (unsigned  char*)bytes;
        for (NSInteger i =0; i < byteRange.length; i++) {
            NSString *hexStr = [NSString stringWithFormat:@"%x", (dataBytes[i]) & 0xff];
            if ([hexStr length] ==2) {
                [string appendString:hexStr];
            } else {
                [string appendFormat:@"0%@", hexStr];
            }
        }
    }];
    
    return string;
}
@end

@implementation NSData (Encrypt)
/**
 *  根据CCOperation，确定加密还是解密
 *  @keySize 密钥大小 128 192 256
 *  @param operation kCCEncrypt -> 加密  kCCDecrypt－>解密
 *  @param key       公钥
 *  @param iv        偏移量
 *
 *  @return 加密或者解密的NSData
 */
- (instancetype)AESKeySize:(NSUInteger)kCCKeySizeAES operation:(CCOperation)operation key:(NSString *)key iv:(NSString *)iv
{
    //如果有base64加密过，则需要base64解密，后续操作使用解编码的data
//    base64Data为加密后base64编码的NSData
//    base64String为base64Data转utf8编码字符串，
//    NSData *encryptData = [[NSData alloc] initWithBase64EncodedString:base64String options:0];
//    NSData *encryptData = [[NSData alloc] initWithBase64EncodedData:base64Data options:0];
    char keyPtr[kCCKeySizeAES + 1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    // iv
//    char ivPtr[kCCBlockSizeAES128 + 1];
//    memset(ivPtr, 0, sizeof(ivPtr));
//    [iv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [self length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesCrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(operation,
                                          kCCAlgorithmAES128,//填充方式
                                          kCCOptionPKCS7Padding|kCCOptionECBMode,      //工作模式
                                          keyPtr,//AES的密钥长度有128字节、192字节、256字节几种，这里举出可能存在的最大长度
                                          kCCKeySizeAES,//密文长度+补位长度
                                          NULL,
                                          [self bytes],//字节大小
                                          dataLength,//字节长度
                                          buffer,
                                          bufferSize,
                                          &numBytesCrypted);
    if (cryptStatus == kCCSuccess) {
        NSData *encryptData = [NSData dataWithBytesNoCopy:buffer length:numBytesCrypted];
        
        //如果需要base64编码，加上下面代码二选一
//        NSString *base64String = [encryptData base64EncodedStringWithOptions:0];
//        NSData *base64Data = [encryptData base64EncodedDataWithOptions:0];
        
        return encryptData;
    }
    free(buffer);
    
    return nil;
}

#pragma mark - AES 加密

- (instancetype)AES128EncryptWithKey:(NSString *)key iv:(NSString *)iv
{
    return [self AESKeySize:kCCKeySizeAES128 operation:kCCEncrypt key:key iv:iv];
}

- (instancetype)AES192EncryptWithKey:(NSString *)key iv:(NSString *)iv
{
    return [self AESKeySize:kCCKeySizeAES192 operation:kCCEncrypt key:key iv:iv];
}

- (instancetype)AES256EncryptWithKey:(NSString *)key iv:(NSString *)iv
{
    return [self AESKeySize:kCCKeySizeAES256 operation:kCCEncrypt key:key iv:iv];
}

#pragma mark - AES 解密

- (instancetype)AES128DecryptWithKey:(NSString *)key iv:(NSString *)iv
{
    return [self AESKeySize:kCCKeySizeAES128 operation:kCCDecrypt key:key iv:iv];
}

- (instancetype)AES192DecryptWithKey:(NSString *)key iv:(NSString *)iv
{
    return [self AESKeySize:kCCKeySizeAES192 operation:kCCDecrypt key:key iv:iv];
}

- (instancetype)AES256DecryptWithKey:(NSString *)key iv:(NSString *)iv
{
    return [self AESKeySize:kCCKeySizeAES256 operation:kCCDecrypt key:key iv:iv];
}

#pragma mark - DES 加密

- (instancetype)DESEncryptWithKey:(NSString *)key iv:(NSString *)iv {
    char keyPtr[kCCKeySizeAES256+1];//密钥长度+1，可大不可小
    bzero(keyPtr, sizeof(keyPtr));
    
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [self length];
    size_t bufferSize = dataLength + kCCBlockSizeDES;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          kCCAlgorithmDES,
                                          kCCOptionPKCS7Padding | kCCOptionECBMode,
                                          keyPtr,
                                          kCCBlockSizeDES,//
                                          NULL,
                                          [self bytes],
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
    }
    
    free(buffer);
    return nil;
}
#pragma mark - DES 解密
//des解密
- (instancetype)DESDecryptWithKey:(NSString *)key iv:(NSString *)iv {
    char keyPtr[kCCKeySizeAES256+1];
    bzero(keyPtr, sizeof(keyPtr));
    
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [self length];
    
    size_t bufferSize = dataLength + kCCBlockSizeDES;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmDES,
                                          kCCOptionPKCS7Padding | kCCOptionECBMode,
                                          keyPtr,
                                          kCCBlockSizeDES,
                                          NULL,
                                          [self bytes],
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesDecrypted);
    
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    }
    
    free(buffer);
    return nil;
}
@end
