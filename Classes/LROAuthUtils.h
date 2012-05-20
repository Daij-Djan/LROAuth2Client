//
//  LROAuthUtils.h
//  LROAuth2Client
//
//  Created by Dominik Pich on 05.01.12.
//  Copyright (c) 2012 doo GmbH. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface LROAuthUtils : NSObject

+ (NSString *)SHA1forData:(NSData *)data;
+ (NSString *)SHA256forData:(id)data;
+ (NSString *)signString:(NSString*)data usingHMACSHA1withKey:(NSString *)key;
+ (NSString *)signString:(NSString*)data usingHMACSHA256withKey:(NSString *)key;

@end
