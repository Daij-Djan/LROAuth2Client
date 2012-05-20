//
//  LROAuth2Client.h
//  LROAuth2Client
//
//  Created by Luke Redpath on 14/05/2010.
//  Copyright 2010 LJR Software Limited. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "ASIHTTPRequestDelegate.h"
#import "LROAuth2ClientDelegate.h"

@class LROAuth2AccessToken;

@interface LROAuth2Client : NSObject <ASIHTTPRequestDelegate> {
  NSString *clientID;
  NSString *clientSecret;
  NSURL *redirectURL;
  NSURL *cancelURL;
  NSURL *userURL;
  NSURL *tokenURL;
  LROAuth2AccessToken *accessToken;
  NSMutableArray *requests;
  __weak id<LROAuth2ClientDelegate> delegate;
  BOOL debug;
  
 @private
  BOOL isVerifying;   
}
@property (nonatomic, copy) NSString *clientID;
@property (nonatomic, copy) NSString *clientSecret;
@property (nonatomic, copy) NSURL *redirectURL;
@property (nonatomic, copy) NSURL *cancelURL;
@property (nonatomic, copy) NSURL *userURL;
@property (nonatomic, copy) NSURL *tokenURL;
@property (nonatomic, readonly) LROAuth2AccessToken *accessToken;
@property (nonatomic, weak) id<LROAuth2ClientDelegate> delegate;
@property (nonatomic, assign) BOOL debug;

- (id)initWithClientID:(NSString *)_clientID 
                secret:(NSString *)_secret 
           redirectURL:(NSURL *)url;

- (NSURLRequest *)userAuthorizationRequestWithParameters:(NSDictionary *)additionalParameters;
- (void)verifyAuthorizationWithAccessCode:(NSString *)accessCode;
- (void)tryToGetAccessTokenForClientCredentials;
- (void)refreshAccessToken:(LROAuth2AccessToken *)_accessToken;
- (void)directlyRefreshAccessToken:(LROAuth2AccessToken *)_accessToken;
- (void)extractAccessCodeFromCallbackURL:(NSURL *)url;

@end