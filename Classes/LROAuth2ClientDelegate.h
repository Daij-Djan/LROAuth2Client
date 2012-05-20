//
//  LROAuth2ClientDelegate.h
//  LROAuth2Client
//
//  Created by Luke Redpath on 14/05/2010.
//  Copyright 2010 LJR Software Limited. All rights reserved.
//

@class LROAuth2Client;

#if TARGET_OS_IPHONE
#import <UIKit/UIKit.h>
@protocol LROAuth2ClientDelegate <UIWebViewDelegate>
#else
#import <WebKit/WebKit.h>
@protocol LROAuth2ClientDelegate
#endif

@required
- (void)oauthClientDidFailToReceiveAccessToken:(LROAuth2Client *)client;
- (void)oauthClient:(LROAuth2Client *)client didReceiveAccessTokenWith:(NSDictionary*)authorizationData;
- (void)oauthClientDidFailToRefreshAccessToken:(LROAuth2Client *)client;
- (void)oauthClient:(LROAuth2Client *)client didRefreshAccessTokenWith:(NSDictionary*)authorizationData;

//@optional
- (void)oauthClientDidFailToReceiveAccessCode:(LROAuth2Client *)client;
- (void)oauthClientDidReceiveAccessCode:(LROAuth2Client *)client;
- (void)oauthClientDidCancel:(LROAuth2Client *)client;

@end
