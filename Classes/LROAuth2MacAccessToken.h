//
//  LROAuth2MacAccessToken.h
//  LROAuth2Client
//
//  Created by Dominik Pich on 05.01.12.
//  Copyright (c) 2012 doo GmbH. All rights reserved.
//

#import "LROAuth2AccessToken.h"

enum MacAlgo {
	MacAlgoSha1,
	MacAlgoSha256
};

@interface LROAuth2MacAccessToken : LROAuth2AccessToken {
	NSString *_secret;
	enum MacAlgo _algorithm;
	NSTimeInterval _timeOfIssue;
	NSString *_randomString;
	
	BOOL _test;
}

//test this
+ (void) testTokenAndTestRequest;

@end
