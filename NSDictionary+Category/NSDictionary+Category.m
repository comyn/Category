//
//  NSDictionary+Category.m
//  线程
//
//  Created by comyn on 2018/3/2.
//  Copyright © 2018年 comyn. All rights reserved.
//

#import "NSDictionary+Category.h"

@implementation NSDictionary (Category)


/**
 控制台打印：unicode转汉字

 @param locale locale description
 @param level level description
 @return return value description
 */
- (NSString *)descriptionWithLocale:(id)locale indent:(NSUInteger)level {
    NSMutableString *strM = [NSMutableString stringWithString:@"{\n"];
    [self enumerateKeysAndObjectsUsingBlock:^(id  _Nonnull key, id  _Nonnull obj, BOOL * _Nonnull stop) {
        [strM appendFormat:@"\t%@ = %@;\n", key, obj];
    }];
    
    [strM appendString:@"}\n"];
    return  strM.copy;
}
@end
