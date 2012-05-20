//
//  LROAuth2BearerAccessToken.m
//  LROAuth2Client
//
//  Created by Dominik Pich on 05.01.12.
//  Copyright (c) 2012 doo GmbH. All rights reserved.
//

#import "LROAuth2BearerAccessToken.h"
#import "ASIHTTPRequest.h"

@implementation LROAuth2BearerAccessToken

- (void)refreshFromAuthorizationResponse:(NSDictionary *)data;
{
	_rawData = [data copy];
	
	if([_rawData objectForKey:@"expires_in"]) {
		NSTimeInterval issueTime = (NSTimeInterval)[[_rawData objectForKey:@"issue_time"] intValue];
		NSTimeInterval expiresIn = (NSTimeInterval)[[_rawData objectForKey:@"expires_in"] intValue];
		_expiresAt = [[NSDate alloc] initWithTimeIntervalSince1970:issueTime + expiresIn];
	}
	else {
		_expiresAt = [NSDate distantFuture];
	}
	
	_accessToken = [_rawData objectForKey:@"access_token"];
	_refreshToken = [_rawData objectForKey:@"refresh_token"]; 
	
}

- (void)authorizeHTTPRequest:(ASIHTTPRequest*)request {
	NSString *authorizationString = [NSString stringWithFormat:@"Bearer %@", _accessToken];
	[request addRequestHeader:OAuthRequestHeaderAuthorizationKey value:authorizationString];
}
@end
