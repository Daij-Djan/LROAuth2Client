//
//  LROAuth2AccessToken.h
//  LROAuth2Client
//
//  Created by Luke Redpath on 14/05/2010.
//  Copyright 2010 LJR Software Limited. All rights reserved.
//

#import <Foundation/Foundation.h>

#if TARGET_OS_IPHONE
#define NSEqualToComparison 0
#endif

#define OAuthRequestHeaderAuthorizationKey @"Authorization"

@class ASIHTTPRequest;

@interface LROAuth2AccessToken : NSObject <NSCoding> {
@protected
	NSString *_accessToken;
	NSString *_refreshToken;
	NSDate *_expiresAt;
	NSDictionary *_rawData;
}
@property (strong, readonly) NSString *accessToken;
@property (strong, readonly) NSString *refreshToken;
@property (strong, readonly) NSDate *expiresAt;
@property (strong, readonly) NSDictionary *rawData;
@property (assign, readonly) BOOL hasExpired;

+ (LROAuth2AccessToken*)tokenWithAuthorizationResponse:(NSDictionary *)data;
- (void)refreshFromAuthorizationResponse:(NSDictionary *)_data;
- (void)authorizeHTTPRequest:(ASIHTTPRequest*)request;
@end
