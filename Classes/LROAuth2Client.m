//
//  LROAuth2Client.m
//  LROAuth2Client
//
//  Created by Luke Redpath on 14/05/2010.
//  Copyright 2010 LJR Software Limited. All rights reserved.
//

#import "LROAuth2Client.h"
#import "ASIHTTPRequest.h"
#import "NSURL+QueryInspector.h"
#import "LROAuth2AccessToken.h"
#import "NSDictionary+QueryString.h"

#pragma mark -

@implementation LROAuth2Client

@synthesize clientID;
@synthesize clientSecret;
@synthesize redirectURL;
@synthesize cancelURL;
@synthesize userURL;
@synthesize tokenURL;
@synthesize delegate;
@synthesize accessToken;
@synthesize debug;

- (id)initWithClientID:(NSString *)_clientID 
                secret:(NSString *)_secret 
           redirectURL:(NSURL *)url;
{
  if (self = [super init]) {
    clientID = [_clientID copy];
    clientSecret = [_secret copy];
    redirectURL = [url copy];
    requests = [[NSMutableArray alloc] init];
    debug = NO;
  }
  return self;
}

- (void)dealloc;
{
  for (ASIHTTPRequest *request in requests) {
    [request setDelegate:nil];
    [request cancel];
  }
//  [requests release];
//  [accessToken release];
//  [clientID release];
// [clientSecret release];
//  [userURL release];
//  [tokenURL release];
//  [redirectURL release];
//  [cancelURL release];
//  [super dealloc];
}

#pragma mark -
#pragma mark Authorization

- (NSURLRequest *)userAuthorizationRequestWithParameters:(NSDictionary *)additionalParameters;
{
  NSDictionary *params = [NSMutableDictionary dictionary];
//	[params setValue:@"***" forKey:@"state"];
  [params setValue:clientID forKey:@"client_id"];
  [params setValue:[redirectURL absoluteString] forKey:@"redirect_uri"];
  [params setValue:@"code" forKey:@"response_type"];
  
  if (additionalParameters) {
    for (NSString *key in additionalParameters) {
      [params setValue:[additionalParameters valueForKey:key] forKey:key];
    }
  }  
  NSURL *fullURL = [NSURL URLWithString:[[self.userURL absoluteString] stringByAppendingFormat:@"?%@", [params stringWithFormEncodedComponents]]];
  NSMutableURLRequest *authRequest = [NSMutableURLRequest requestWithURL:fullURL];
  [authRequest setHTTPMethod:@"GET"];

	return [authRequest copy];// autorelease];
}

- (void)verifyAuthorizationWithAccessCode:(NSString *)accessCode;
{
  @synchronized(self) {
    if (isVerifying) return; // don't allow more than one auth request
    
    isVerifying = YES;
    
    NSDictionary *params = [NSMutableDictionary dictionary];
    [params setValue:@"authorization_code" forKey:@"grant_type"]; 
    [params setValue:[redirectURL absoluteString] forKey:@"redirect_uri"];
    [params setValue:accessCode forKey:@"code"];

    ASIHTTPRequest *request = [ASIHTTPRequest requestWithURL:self.tokenURL];
    [request setRequestMethod:@"POST"];
    [request addRequestHeader:@"Content-Type" value:@"application/x-www-form-urlencoded"];

    [request appendPostData:[[params stringWithFormEncodedComponents] dataUsingEncoding:NSUTF8StringEncoding]];
		
	  //use for basic HTTP authentication	  
	[request addBasicAuthenticationHeaderWithUsername:clientID
										  andPassword:clientSecret];
    [request setDelegate:self];
    [requests addObject:request];
    [request startAsynchronous];
  }
}

- (void)tryToGetAccessTokenForClientCredentials
{
    @synchronized(self) {
        if (isVerifying) return; // don't allow more than one auth request
        
        isVerifying = YES;
        
        NSDictionary *params = [NSMutableDictionary dictionary];
        [params setValue:@"client_credentials" forKey:@"grant_type"]; 
        
        ASIHTTPRequest *request = [ASIHTTPRequest requestWithURL:self.tokenURL];
        [request setRequestMethod:@"POST"];
        [request addRequestHeader:@"Content-Type" value:@"application/x-www-form-urlencoded"];
        
        [request appendPostData:[[params stringWithFormEncodedComponents] dataUsingEncoding:NSUTF8StringEncoding]];
		
        //use for basic HTTP authentication	  
        [request addBasicAuthenticationHeaderWithUsername:clientID
                                              andPassword:clientSecret];
        [request setDelegate:self];
        [requests addObject:request];
        [request startAsynchronous];
    }
}

- (void)refreshAccessToken:(LROAuth2AccessToken *)_accessToken;
{
	accessToken = _accessToken;// retain];
  
  NSDictionary *params = [NSMutableDictionary dictionary];
  [params setValue:@"refresh_token" forKey:@"grant_type"];
  [params setValue:[redirectURL absoluteString] forKey:@"redirect_uri"];
  [params setValue:_accessToken.refreshToken forKey:@"refresh_token"];

//	//for now just post it
//  [params setValue:clientID forKey:@"client_id"];
//  [params setValue:clientSecret forKey:@"client_g"];
	
  ASIHTTPRequest *request = [ASIHTTPRequest requestWithURL:self.tokenURL];
  [request setRequestMethod:@"POST"];
  [request addRequestHeader:@"Content-Type" value:@"application/x-www-form-urlencoded"];

	//use for basic HTTP authentication	  
	[request addBasicAuthenticationHeaderWithUsername:clientID
										  andPassword:clientSecret];
	
  [request appendPostData:[[params stringWithFormEncodedComponents] dataUsingEncoding:NSUTF8StringEncoding]];
  [request setDelegate:self];
  [requests addObject:request];
  [request startAsynchronous];
}

- (void)directlyRefreshAccessToken:(LROAuth2AccessToken *)_accessToken {
	accessToken = _accessToken;// retain];
    
    NSDictionary *params = [NSMutableDictionary dictionary];
    [params setValue:@"refresh_token" forKey:@"grant_type"];
    [params setValue:[redirectURL absoluteString] forKey:@"redirect_uri"];
    [params setValue:_accessToken.refreshToken forKey:@"refresh_token"];
    
    //	//for now just post it
    //  [params setValue:clientID forKey:@"client_id"];
    //  [params setValue:clientSecret forKey:@"client_g"];
	
    ASIHTTPRequest *request = [ASIHTTPRequest requestWithURL:self.tokenURL];
    [request setRequestMethod:@"POST"];
    [request addRequestHeader:@"Content-Type" value:@"application/x-www-form-urlencoded"];
    
	//use for basic HTTP authentication	  
	[request addBasicAuthenticationHeaderWithUsername:clientID
										  andPassword:clientSecret];
	
    [request appendPostData:[[params stringWithFormEncodedComponents] dataUsingEncoding:NSUTF8StringEncoding]];

    __weak ASIHTTPRequest *r = request;
    [request setCompletionBlock:^{
        NSData* data = [r responseData];
        NSError *parseError = nil;
        NSDictionary *authorizationData = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableContainers error:&parseError];
        
        //see if we can get a valid JSON object
        if (parseError) {
            // try and decode the response body as a query string instead
            NSString *responseString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            authorizationData = [NSDictionary dictionaryWithFormEncodedString:responseString];
            //[responseString release];
            if ([authorizationData valueForKey:@"access_token"] == nil) { 
                // TODO handle complete parsing failure
                NSLog(@"Unhandled parsing failure when getting token");
                
                authorizationData = nil;
            }
        }  
        //error out
        if ([authorizationData valueForKey:@"error"] != nil) { 		
            authorizationData = nil;
        }
        
        if(authorizationData) {
            NSNumber *gmtTime = [NSNumber numberWithDouble:[[NSDate date] timeIntervalSince1970]];
            [(NSMutableDictionary*)authorizationData setObject:gmtTime forKey:@"issue_time"];
            
            if (accessToken == nil) {
                accessToken = [LROAuth2AccessToken tokenWithAuthorizationResponse:authorizationData];
                //    if ([self.delegate respondsToSelector:@selector(oauthClientDidReceiveAccessToken:)]) {
                [self.delegate oauthClient:self didReceiveAccessTokenWith:authorizationData];
                //    } 
            } else {
                [accessToken refreshFromAuthorizationResponse:authorizationData];
                //    if ([self.delegate respondsToSelector:@selector(oauthClientDidRefreshAccessToken:)]) {
                [self.delegate oauthClient:self didRefreshAccessTokenWith:authorizationData];
                //    }
            }
        }
        else {
            NSLog(@"%@", [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]);
            if (accessToken == nil) {
                [self.delegate oauthClientDidFailToReceiveAccessToken:self];
            } else {
                NSLog(@"fail for %@", [accessToken rawData]);
                [self.delegate oauthClientDidFailToRefreshAccessToken:self];
            }
        }
    }];
    [request setFailedBlock:^{
        NSLog(@"[oauth] request failed with code %d, %@", [r responseStatusCode], [r responseString]);
        if (r.completionBlock)
			r.completionBlock();
    }];
    
    [request startSynchronous];
}

#pragma mark -
#pragma mark ASIHTTPRequestDelegate methods

- (void)requestStarted:(ASIHTTPRequest *)request
{
  if (self.debug) {
    NSLog(@"[oauth] starting verification request");
  }
}

- (void)requestFinished:(ASIHTTPRequest *)request
{
	NSData* data = [request responseData];
	//  if( [request isResponseCompressed]) {
	//    data = [request uncompressZippedData:rawData];
	//  }
    
	NSError *parseError = nil;
	NSDictionary *authorizationData = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableContainers error:&parseError];
	
	//see if we can get a valid JSON object
	if (parseError) {
		// try and decode the response body as a query string instead
		NSString *responseString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
		authorizationData = [NSDictionary dictionaryWithFormEncodedString:responseString];
		//[responseString release];
		if ([authorizationData valueForKey:@"access_token"] == nil) { 
			// TODO handle complete parsing failure
			NSAssert(NO, @"Unhandled parsing failure");
			
			authorizationData = nil;
		}
	}  
	//error out
	if ([authorizationData valueForKey:@"error"] != nil) { 		
		authorizationData = nil;
	}
	
	if(authorizationData) {
		NSNumber *gmtTime = [NSNumber numberWithDouble:[[NSDate date] timeIntervalSince1970]];
		[(NSMutableDictionary*)authorizationData setObject:gmtTime forKey:@"issue_time"];
		 
		if (accessToken == nil) {
			accessToken = [LROAuth2AccessToken tokenWithAuthorizationResponse:authorizationData];
			//    if ([self.delegate respondsToSelector:@selector(oauthClientDidReceiveAccessToken:)]) {
			[self.delegate oauthClient:self didReceiveAccessTokenWith:authorizationData];
			//    } 
		} else {
			[accessToken refreshFromAuthorizationResponse:authorizationData];
			//    if ([self.delegate respondsToSelector:@selector(oauthClientDidRefreshAccessToken:)]) {
			[self.delegate oauthClient:self didRefreshAccessTokenWith:authorizationData];
			//    }
		}
	}
	else {
		if (accessToken == nil) {
            NSLog(@"%@", [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]);
			[self.delegate oauthClientDidFailToReceiveAccessToken:self];
		} else {
			[self.delegate oauthClientDidFailToRefreshAccessToken:self];
		}
	}
	if (self.debug) {
		NSLog(@"[oauth] finished verification request, %@ (%d)", [request responseString], [request responseStatusCode]);
	}
	isVerifying = NO;

	[requests removeObject:request];
}

- (void)requestFailed:(ASIHTTPRequest *)request
{
//  if (self.debug) {
    NSLog(@"[oauth] request failed with code %d, %@", [request responseStatusCode], [request responseString]);
	[self requestFinished:request];
//  }
} 

- (void)extractAccessCodeFromCallbackURL:(NSURL *)callbackURL;
{
	NSString *accessCode = [[callbackURL queryDictionary] valueForKey:@"code"];
	
	if (accessCode.length == 0) {
		if ([(id)self.delegate respondsToSelector:@selector(oauthClientDidFailToReceiveAccessCode:)])
			[self.delegate oauthClientDidFailToReceiveAccessCode:self];
		return;	
	}
	
	if ([(id)self.delegate respondsToSelector:@selector(oauthClientDidReceiveAccessCode:)]) {
		[self.delegate oauthClientDidReceiveAccessCode:self];
	}
	[self verifyAuthorizationWithAccessCode:accessCode];
}

@end