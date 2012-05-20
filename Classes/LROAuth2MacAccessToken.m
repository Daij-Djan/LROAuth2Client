//
//  LROAuth2MacAccessToken.m
//  LROAuth2Client
//
//  Created by Dominik Pich on 05.01.12.
//  Copyright (c) 2012 doo GmbH. All rights reserved.
//

#import "LROAuth2MacAccessToken.h"
#import "LROAuthUtils.h"
#import "ASIHTTPRequest.h"

@implementation LROAuth2MacAccessToken

+ (void) testTokenAndTestRequest {
//from doc
	NSDictionary *data = [NSDictionary dictionaryWithObjectsAndKeys:
						  @"jd93dh9dh39D", @"access_token",
						  @"8yfrufh348h", @"secret",
						  @"hmac-sha-1", @"algorithm",
						  @"0", @"issue_time",
						  @"", @"refresh_token",
						  @"", @"expires_in",
						  @"1", @"test",
						  nil];
	
	LROAuth2MacAccessToken *token = [[LROAuth2MacAccessToken alloc] init];
	[token refreshFromAuthorizationResponse:data];
	
	ASIHTTPRequest *request = [ASIHTTPRequest requestWithURL:[NSURL URLWithString:@"http://example.com:80/request"]];
	[request setRequestMethod:@"POST"];
	[request setPostBody:[[@"hello=world%21" dataUsingEncoding:NSUTF8StringEncoding] mutableCopy]];
	
	[token authorizeHTTPRequest:request];
	
	[request startSynchronous];
	NSLog(@"%@", [request responseString]);
}

- (void)refreshFromAuthorizationResponse:(NSDictionary *)data;
{
	//TODO make this method a BOOL and check the data
	
	_rawData = [data copy];
	
	//get data
	_accessToken = [_rawData objectForKey:@"access_token"];//The MAC key identifier.
	_secret = [_rawData objectForKey:@"secret"];//MAC key
	_algorithm = ([[_rawData objectForKey:@"algorithm"] compare:@"hmac-sha-1" options:NSCaseInsensitiveSearch]==NSEqualToComparison) ? MacAlgoSha1 : MacAlgoSha256;//algorithm
	_timeOfIssue = [[_rawData objectForKey:@"issue_time"] doubleValue];//issue time
	
	_refreshToken = [_rawData objectForKey:@"refresh_token"]; 

	if([_rawData objectForKey:@"expires_in"]) {
		NSTimeInterval issueTime = (NSTimeInterval)[[_rawData objectForKey:@"issue_time"] intValue];
		NSTimeInterval expiresIn = (NSTimeInterval)[[_rawData objectForKey:@"expires_in"] intValue];
		_expiresAt = [[NSDate alloc] initWithTimeIntervalSince1970:issueTime + expiresIn];
	}
	else {
		_expiresAt = [NSDate distantFuture];
	}
	
//	//random value for use in nonce
//	_randomString = (__bridge_transfer NSString*)CFUUIDCreateString(NULL, CFUUIDCreate(NULL));

	//if test, we modify the random data
	_test = [[_rawData objectForKey:@"test"] boolValue];
//	if(_test) {
//		_randomString = @"di3hvdf8";
//	}
}

- (void)authorizeHTTPRequest:(ASIHTTPRequest *)request {
	// Jump through hoops while eating hot food
	//according to http://tools.ietf.org/html/draft-hammer-oauth-v2-mac-token-05
	
	//random value for use in nonce
	_randomString = (__bridge_transfer NSString*)CFUUIDCreateString(NULL, CFUUIDCreate(NULL));
	if(_test) {
		_randomString = @"di3hvdf8";
	}

	//age for use in nonce
	NSTimeInterval age = [[NSDate date] timeIntervalSince1970] - _timeOfIssue;
	if(_test)
		age = 273156;
	
	//build a nonce
	NSString *nonce = [NSString stringWithFormat:@"%lu:%@", (NSUInteger)age, _randomString];
	
	//get parts
	NSString *method = [request.requestMethod uppercaseString];
	NSString *path = request.url.path;
	NSString *url = request.url.query.length ? [NSString stringWithFormat:@"%@?%@", path, request.url.query] : path;
	NSString *host = request.url.host;
             
	NSString *port;
    
    if([request.url.port unsignedIntegerValue]==0)
    {
        if( [request.url.scheme isEqualToString:@"http"])
            port = @"80";
        else if( [request.url.scheme isEqualToString:@"https"])
            port = @"443";
    }
    else
        port = [NSString stringWithFormat:@"%lu",[request.url.port unsignedIntegerValue]];
	
	//get bodyHash
	NSData *body = request.postBody;
	NSString *bodyHash = @"";
	
//	if(!body.length)
//		body = [@"" dataUsingEncoding:NSUTF8StringEncoding];
	
	if(_algorithm == MacAlgoSha1) {
		bodyHash = [LROAuthUtils SHA1forData:body];
	} else if(_algorithm == MacAlgoSha256) {
		bodyHash = [LROAuthUtils SHA256forData:body];
	}
	
	//normalize
	NSString *extension = @"";
	char nl = 0x0A; //define our newline character
	NSString *normalizedRequest = [NSString stringWithFormat:@"%@%c%@%c%@%c%@%c%@%c%@%c%@%c", 
								   nonce, nl, method, nl, url, nl, host, nl, port, nl, bodyHash, nl, extension, nl];

	//sign
	NSString *signedRequest = nil;
	if(_algorithm == MacAlgoSha1) {
		signedRequest = [LROAuthUtils signString:normalizedRequest usingHMACSHA1withKey:_secret];
	} else if(_algorithm == MacAlgoSha256) {
		signedRequest = [LROAuthUtils signString:normalizedRequest usingHMACSHA256withKey:_secret];
	}

	//add it all to the auth header
	NSString *authorizationString = [NSString stringWithFormat:@"MAC id=\"%@\",nonce=\"%@\",mac=\"%@\"", _accessToken, nonce, signedRequest];
    [request addRequestHeader:OAuthRequestHeaderAuthorizationKey value:authorizationString];
}

@end
