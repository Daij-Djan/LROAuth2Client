//
//  LROAuthUtils.m
//  LROAuth2Client
//
//  Created by Dominik Pich on 05.01.12.
//  Copyright (c) 2012 doo GmbH. All rights reserved.
//

#import "LROAuthUtils.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#include "Base64Transcoder.h"

@implementation LROAuthUtils

+ (NSString *)SHA1forData:(NSData *)data {
	unsigned char digest[CC_SHA1_DIGEST_LENGTH];
	if (CC_SHA1([data bytes], (CC_LONG)[data length], digest)) {
		//Base64 Encoding
		char base64Result[32];
		size_t theResultLength = 32;
		Base64EncodeData(digest, CC_SHA1_DIGEST_LENGTH, base64Result, &theResultLength);
		NSData *theData = [NSData dataWithBytes:base64Result length:theResultLength];
		NSString *base64EncodedResult = [[NSString alloc] initWithData:theData encoding:NSUTF8StringEncoding];		
		return base64EncodedResult;
	}	
	return nil;
}

+ (NSString *)SHA256forData:(id)data {
	unsigned char digest[CC_SHA256_DIGEST_LENGTH];
	unsigned char *ret;
	
	if([data isKindOfClass:[NSString class]]) 
		ret = CC_SHA256([data UTF8String], (CC_LONG)[data length], digest);
	else
		ret = CC_SHA256([data bytes], (CC_LONG)[data length], digest);
	
	if(ret) {
		//Base64 Encoding
		char base64Result[55];
		size_t theResultLength = 55;
		Base64EncodeData(digest, CC_SHA256_DIGEST_LENGTH, base64Result, &theResultLength);
		NSData *theData = [NSData dataWithBytes:base64Result length:theResultLength];
		NSString *base64EncodedResult = [[NSString alloc] initWithData:theData encoding:NSUTF8StringEncoding];		
		return base64EncodedResult;
	}	
	return nil;
}

#pragma mark -

+ (NSString *)signString:(NSString*)data usingHMACSHA1withKey:(NSString *)key
{
	//sha
	NSData *secretData = [key dataUsingEncoding:NSUTF8StringEncoding];
    NSData *clearTextData = [data dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char result[CC_SHA1_DIGEST_LENGTH];
	CCHmac(kCCHmacAlgSHA1, [secretData bytes], [secretData length], [clearTextData bytes], [clearTextData length], result);   

	//Base64 Encoding
    char base64Result[32];
    size_t theResultLength = 32;
    Base64EncodeData(result, CC_SHA1_DIGEST_LENGTH, base64Result, &theResultLength);
    NSData *theData = [NSData dataWithBytes:base64Result length:theResultLength];
    
    NSString *base64EncodedResult = [[NSString alloc] initWithData:theData encoding:NSUTF8StringEncoding];
    
    return base64EncodedResult;
}

+ (NSString *)signString:(NSString*)data usingHMACSHA256withKey:(NSString *)key
{
	unsigned char buf[CC_SHA256_DIGEST_LENGTH];
	CCHmac(kCCHmacAlgSHA256, [key UTF8String], [key length], [data UTF8String], [data length], buf);

	//sha
	NSData *secretData = [key dataUsingEncoding:NSUTF8StringEncoding];
    NSData *clearTextData = [data dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char result[CC_SHA256_DIGEST_LENGTH];
	CCHmac(kCCHmacAlgSHA256, [secretData bytes], [secretData length], [clearTextData bytes], [clearTextData length], result);

	//Base64 Encoding    
    char base64Result[55];
    size_t theResultLength = 55;
    Base64EncodeData(result, CC_SHA256_DIGEST_LENGTH, base64Result, &theResultLength);
    NSData *theData = [NSData dataWithBytes:base64Result length:theResultLength];
    
    NSString *base64EncodedResult = [[NSString alloc] initWithData:theData encoding:NSUTF8StringEncoding];
    
    return base64EncodedResult;
}

@end
