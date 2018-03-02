//
//  NSString+Category.m
//  线程
//
//  Created by comyn on 2018/2/28.
//  Copyright © 2018年 comyn. All rights reserved.
//

#import "NSString+Category.h"

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

@end
