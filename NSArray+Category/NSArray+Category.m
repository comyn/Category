//
//  NSArray+Category.m
//  线程
//
//  Created by comyn on 2018/3/2.
//  Copyright © 2018年 comyn. All rights reserved.
//

#import "NSArray+Category.h"

@implementation NSArray (Category)


/**
 unicode编码字符
 Xcode8以后，字典和数组的descriptionWithLocale都不再被调用。后来使用
 - (NSString *)descriptionWithLocale:(id)locale indent:(NSUInteger)level来取代
 
 @param locale ***
 @return 汉字字符
 */
- (NSString *)descriptionWithLocale:(id)locale indent:(NSUInteger)level{
    
    NSMutableString *mStr = [NSMutableString string];
    [mStr appendString:@"(\r\n"];
    [self enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        [mStr appendFormat:@"\t%@,\r\n", obj];
        NSLog(@"obj=%@",obj);
    }];

    [mStr appendString:@")"];
    return mStr.copy;
    
}
@end
