//
//  NSString+Category.h
//  线程
//
//  Created by comyn on 2018/2/28.
//  Copyright © 2018年 comyn. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSString (Category)


/**
 根据url路径中的文件名，获取缓存的文件、图片等路径
 临时文件，非重要
 
 @return 返回路径
 */
- (instancetype)appendCache;

/**
 根据url路径中的文件名，获取缓存的文件、图片等路径
 临时文件，用完就删除了
 
 @return 返回路径
 */
- (instancetype)appendTemp;

/**
 根据url路径中的文件名，获取缓存的文件、图片等路径
 文件，重要永久
 
 @return 返回路径
 */
- (instancetype)appendDocument;


//编码
- (instancetype)base64Encode;
//解码
- (instancetype)base64Decode;
//不可逆加密，用于校验
- (instancetype)md5String;
- (instancetype)sha1String;
- (instancetype)sha256String;
// NSData 转 hexString
- (instancetype)hexStrWithData:(NSData *)data;
- (instancetype)hexStringWithData:(NSData *)data;
@end

@interface NSString (RSAEncrypt)
- (instancetype)RSAEncryptWithPublicKeyFile:(NSString *)path;
- (instancetype)RSADecryptWithPrivateKeyFile:(NSString *)path password:(NSString *)password;

- (instancetype)RSAEncryptWithPublicKey:(NSString *)publicKey;
- (instancetype)RSADecryptWithPrivateKey:(NSString *)privateKey;

@end
