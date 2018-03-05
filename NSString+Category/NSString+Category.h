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


/**
 base64编码

 @return base64字符串
 */
- (instancetype)base64Encode;


/**
 base64解码

 @return 解码后的字符串
 */
- (instancetype)base64Decode;

- (instancetype)md5String;
@end
