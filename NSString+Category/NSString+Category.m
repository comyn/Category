//
//  NSString+Category.m
//  线程
//
//  Created by comyn on 2018/2/28.
//  Copyright © 2018年 comyn. All rights reserved.
//

#import "NSString+Category.h"
#import <CommonCrypto/CommonCrypto.h>

@implementation NSString (Category)

- (instancetype)appendCache {
    return [[NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES) lastObject] stringByAppendingPathComponent:self.lastPathComponent];
}

- (instancetype)appendTemp {
    return [NSTemporaryDirectory() stringByAppendingPathComponent:self.lastPathComponent];
}

- (instancetype)appendDocument {
    return [[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) lastObject] stringByAppendingPathComponent:self.lastPathComponent];
}

- (instancetype)base64Encode {
    NSData *data = [self dataUsingEncoding:NSUTF8StringEncoding];
    return [data base64EncodedStringWithOptions:0];
}

- (instancetype)base64Decode {
    NSData *data = [[NSData alloc] initWithBase64EncodedString:self options:0];
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

# pragma mark - 散列算法

- (instancetype)md5String {
    const char *str = self.UTF8String;
    uint8_t buffer[CC_MD5_DIGEST_LENGTH];
    
    CC_MD5(str, (CC_LONG)strlen(str), buffer);
    
    return [self stringFromBytes:buffer length:CC_MD5_DIGEST_LENGTH];
}

#pragma mark - 辅助方法
/**
 返回二进制 Bytes 流的字符串表示形式

 @param bytes 二进制 Bytes 数组
 @param length 数组长度
 @return 字符串表示形式
 */
- (NSString *)stringFromBytes:(uint8_t *)bytes length:(int)length {
    NSMutableString *mStr = [NSMutableString string];
    
    for (int i = 0; i < length; i++) {
        [mStr appendFormat:@"%02x", bytes[i]];//02x,16进制，不够两位补0
    }
    
    return mStr.copy;
}
@end
