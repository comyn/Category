//
//  NSData+AES128.h
//  AESSecret
//
//  Created by comyn on 2018/3/14.
//  Copyright © 2018年 comyn. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSData (Category)

@end

@interface NSData (HexString)
+ (instancetype)dataWithHexStr:(NSString*)str;
- (NSString*)dataToHexStr;
@end

@interface NSData (Encrypt)
/**
 *  加密
 *
 *  @param key 公钥
 *  @param iv  偏移量
 *
 *  @return 加密之后的NSData
 */
- (instancetype)AES128EncryptWithKey:(NSString *)key iv:(NSString *)iv;
- (instancetype)AES192EncryptWithKey:(NSString *)key iv:(NSString *)iv;
- (instancetype)AES256EncryptWithKey:(NSString *)key iv:(NSString *)iv;

- (instancetype)DESEncryptWithKey:(NSString *)key iv:(NSString *)iv;

/**
 *  解密
 *
 *  @param key 公钥
 *  @param iv  偏移量
 *
 *  @return 解密之后的NSData
 */
- (instancetype)AES128DecryptWithKey:(NSString *)key iv:(NSString *)iv;
- (instancetype)AES192DecryptWithKey:(NSString *)key iv:(NSString *)iv;
- (instancetype)AES256DecryptWithKey:(NSString *)key iv:(NSString *)iv;

- (instancetype)DESDecryptWithKey:(NSString *)key iv:(NSString *)iv;

@end

