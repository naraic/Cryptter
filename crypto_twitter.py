#! /usr/bin/env python2

from TwitterAPI import TwitterAPI
import requests
from urlparse import parse_qs
from requests_oauthlib import OAuth1
from credentials import *

oauth = OAuth1(consumer_key, consumer_secret)

r = requests.post(
        url='https://api.twitter.com/oauth/request_token',
        auth=oauth)

credentials = parse_qs(r.content)
access_token_key = credentials.get('oauth_token')[0]
access_token_secret = credentials.get('oauth_token_secret')[0]

print('go here to authorise:\n https://api.twitter.com/oauth/authorize?oauth_token=%s' % access_token_key)

verifier = raw_input('Enter your auth code:')

oauth = OAuth1(consumer_key,
        consumer_secret,
        access_token_key,
        access_token_secret, 
        verifier=verifier)

r = requests.post(url='https://api.twitter.com/oauth/access_token', auth=oauth)
credentials = parse_qs(r.content)
access_token_key = credentials.get('oauth_token')[0]
access_token_secret = credentials.get('oauth_token_secret')[0]
print "access_token_key", access_token_key
print "access_token_secret", access_token_secret

