//
//  LROAuth2AccessToken.m
//  LROAuth2Client
//
//  Created by Luke Redpath on 14/05/2010.
//  Copyright 2010 LJR Software Limited. All rights reserved.
//

#import "LROAuth2AccessToken.h"
#import "LROAuth2MacAccessToken.h"
#import "LROAuth2BearerAccessToken.h"


#pragma mark -

@implementation LROAuth2AccessToken

+ (LROAuth2AccessToken*)tokenWithAuthorizationResponse:(NSDictionary *)data {
	LROAuth2AccessToken *token = nil;
	
	if([[data objectForKey:@"token_type"] compare:@"mac" options:NSCaseInsensitiveSearch]==NSEqualToComparison)
		token = [[LROAuth2MacAccessToken alloc] init];
	else if([[data objectForKey:@"token_type"] compare:@"bearer" options:NSCaseInsensitiveSearch]==NSEqualToComparison)
		token = [[LROAuth2BearerAccessToken alloc] init];
	else
		token = [[LROAuth2AccessToken alloc] init];
	
	[token refreshFromAuthorizationResponse:data];
	return token;
}

@synthesize accessToken=_accessToken;
@synthesize refreshToken=_refreshToken;
@synthesize expiresAt=_expiresAt;
@synthesize rawData=_rawData;

- (void)refreshFromAuthorizationResponse:(NSDictionary *)_data {
	_rawData = [_data copy];
	NSLog(@"Not implemented");
}

- (NSString *)description;
{
  return [NSString stringWithFormat:@"<%@ expiresAt:%@>", NSStringFromClass(self.class), _expiresAt];
}

- (void)authorizeHTTPRequest:(ASIHTTPRequest *)request {
	NSLog(@"Not implemented");
}

#pragma mark -
#pragma mark dynamic properties

- (BOOL)hasExpired;
{
  return ([[NSDate date] earlierDate:_expiresAt] == _expiresAt);
}

#pragma mark -
#pragma mark NSCoding

- (void)encodeWithCoder:(NSCoder *)aCoder
{
  [aCoder encodeObject:_rawData forKey:@"data"];
}

- (id)initWithCoder:(NSCoder *)aDecoder
{
  if (self = [super init]) {
	  NSDictionary *data = [aDecoder decodeObjectForKey:@"data"];
	  [self refreshFromAuthorizationResponse:data];
  }
  return self;
}

@end
