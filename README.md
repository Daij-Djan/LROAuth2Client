<h1>About:</h1>
this project providers an oauth2 library for iOS5 and OSX with support for Bearer token as well as the MAC Token. 

Originally forked from lukedpath's oath library for iOS I expanded and modified it to work as a 'drop-in' static library for OSX 10.7 and IOS 5.
I expanded the original framework to more gracefully handle errors and to be easier to use. Especially I simplified the refreshing of tokens.

It should 'fully' comply to the latest oauth RFC and implemented support for the MAC Token. 

That said, I only implemented what I needed and there's also almost no documentation.

<h1>example usage:</h1>
<h2>get access token:</h2>
<code>
- (void)getToken {
	//prepare client
	NSString *clientID = [_clientCredentials objectForKey:OAuthClientClientId];
	NSString *clientSecret = [_clientCredentials objectForKey:OAuthClientClientSecret];
	NSURL *redirectURL = [NSURL URLWithString:OAuthClientRedirectURL];	
	_client = [[LROAuth2Client alloc] initWithClientID:clientID
	 											secret:clientSecret
	 									   redirectURL:redirectURL];
	_client.delegate = self;
	
	//refresh a store token or get valid token if none stored
	if(_accessToken && _accessToken.hasExpired) {
		NSURL *tokenURL = [NSURL URLWithString:OAuthClientTokenURL];
		_client.tokenURL = tokenURL;

		//refresh it 
		[_client refreshAccessToken:_accessToken];			
	}
	else if(!_accessToken) {
		NSURL *userURL = [NSURL URLWithString:OAuthClientUserURL];
		_client.userURL = userURL;

		//get a token
		NSURLRequest *r = [_client userAuthorizationRequestWithParameters:nil];
        dispatch_async(dispatch_get_main_queue(), ^{
    #if TARGET_OS_IPHONE
				[[UIApplication sharedApplication] openURL:r.URL];
    #else
                [[NSWorkspace sharedWorkspace] openURL:r.URL];
    #endif
            }
        });
	}
}
//called after we presented the url and are ready to continue.
//our client's delegate will be called  after we are done here
- (void)handleAuthorizationURL:(NSURL*)url {
	NSURL *tokenURL = [NSURL URLWithString:OAuthClientTokenURL];
	_client.tokenURL = tokenURL;

	[_client extractAccessCodeFromCallbackURL:url];
}
</code>	

<h2>authorize HTTP Request:</h2>
<code>
//adds Authorization header to request 
- (void)authorizeHTTPRequest:(ASIHTTPRequest*)request {
	if(!_accessToken)
		@throw [NSException exceptionWithName:@"LROAuth2ClientAuthorizationException" reason:@"should authorize, but have no token" userInfo:nil];

	if([_accessToken hasExpired]) {
		@throw [NSException exceptionWithName:@"LROAuth2ClientAuthorizationException" reason:@"should authorize, but needs to refresh the access token" userInfo:nil];
	}
	[_accessToken authorizeHTTPRequest:request];
}
</code>