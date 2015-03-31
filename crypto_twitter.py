#! /usr/bin/env python2

import requests
import re
from urlparse import parse_qs
from requests_oauthlib import OAuth1
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Hash import MD5
import stepic
import json
import StringIO
from PIL import Image

from app_tokens import *

api_url = 'https://api.twitter.com/1.1/'
KEY_LENGTH = 4096 #the best a man can get
private_key = None

def load_user(screen_name):
    with open('tokens/tokens_'+screen_name, 'a+') as token_file:
        token_file.seek(0) # to get back to the beginning
        access_token_key = token_file.readline().strip()
        if access_token_key:
            access_token_secret = token_file.readline().strip()
            with open('keys/key_'+screen_name, 'r') as f:
                p_key = f.read()
            password = raw_input('please enter your password!\n')
            global private_key
            private_key = RSA.importKey(p_key, passphrase=password)
            password = None
            auth = OAuth1(consumer_key, consumer_secret, access_token_key, access_token_secret)
        else:
            #new user - get new keys!
            oauth = OAuth1(consumer_key, consumer_secret)
            r = requests.post(
                    url='https://api.twitter.com/oauth/request_token',
                    auth=oauth)
            credentials = parse_qs(r.content)
            access_token_key = credentials.get('oauth_token')[0]
            access_token_secret = credentials.get('oauth_token_secret')[0]
            print('go here to authorise:\n https://api.twitter.com/oauth/authorize?oauth_token=%s' 
                            % access_token_key)
            verifier = raw_input('Enter your auth code:')
            oauth = OAuth1(consumer_key,
                    consumer_secret,
                    access_token_key,
                    access_token_secret, 
                    verifier=verifier)
            r = requests.post('https://api.twitter.com/oauth/access_token', auth=oauth)
            credentials = parse_qs(r.content)
            access_token_key = credentials.get('oauth_token')[0]
            access_token_secret = credentials.get('oauth_token_secret')[0]
            token_file.write("%s\n" % access_token_key)
            token_file.write("%s\n" % access_token_secret)
            auth = OAuth1(consumer_key, consumer_secret, access_token_key, access_token_secret)
            create_key(auth)
        return auth

def upload_profile_pic(auth, media):
    endpoint = 'account/update_profile_image.json'
    files = {'image':('test.png', media)}
    r = requests.post(api_url+endpoint, files=files, auth=auth) 
    return r.status_code

def upload_media(auth, media):
    endpoint = 'https://upload.twitter.com/1.1/media/upload.json'
    files = {'media':('test.png', media)}
    r = requests.post(endpoint, files=files, auth=auth) 
    print r.text
    r = json.loads(r.text)
    return r["media_id"]

def get_Image_from_user(user):
    img_url = re.sub('_normal.png$', '.png', user['profile_image_url'])
    if not img_url:
        print "get placeholder"
    res = requests.get(img_url)
    stream = StringIO.StringIO(res.content)
    return Image.open(stream)

def get_Image_from_url(url):
    res = requests.get(url)
    stream = StringIO.StringIO(res.content)
    return Image.open(stream)

def load_img_from_file(file):
    with open(file) as p:
        pic = p.read()
    print len(pic)
    stream = StringIO.StringIO(pic)
    return Image.open(stream)

def get_public_key(auth, user_id=None, screen_name=None):
    if not user_id and not screen_name:
        print 'ERROR'
        return 
    endpoint = 'users/show.json'
    payload = {"user_id":user_id, "screen_name":screen_name}
    r = requests.get(api_url+endpoint, params=payload,auth=auth)
    user = json.loads(r.text)
    img = get_Image_from_user(user)
    pubKey = RSA.importKey(stepic.decode(img))
    return pubKey 


def create_key(auth): 
    endpoint = 'account/verify_credentials.json'
    r = requests.get(api_url + endpoint, auth=auth)
    user = json.loads(r.text)
    screen_name = user['screen_name']
    img_data = get_Image_from_user(user)
    random_gen = Random.new().read
    keypair = RSA.generate(KEY_LENGTH, random_gen)
    mypub = keypair.publickey().exportKey()
    secret = raw_input('''input a password to protect your key! 
                            as large as humanely possible, or, larger!\n''')
    pwed_key = keypair.exportKey('PEM', secret, pkcs=1)
    with open('keys/key_'+screen_name, 'w') as f:
        f.write(pwed_key)
    stepic.encode_inplace(img_data, mypub)
    img_data.save('/tmp/test.png')
    with open('/tmp/test.png') as f:
        p = f.read()
    upload_profile_pic(auth, p)
    #print stepic.decode(img_data)
    #key = get_public_key(auth, screen_name='69inthesunshine')
    #print key.exportKey()
'''
    with open(user+'_profile.png', 'wb') as profile_pic:
        profile_pic.write(img_data)
        '''
def tweet_friend(auth, screen_name, message):
    pub = get_public_key(auth, screen_name=screen_name)
    seed = Random.new().read
    mess = pub.encrypt(message, seed)
    img_data = load_img_from_file('new_template.png')
    stepic.encode_inplace(img_data, mess[0])
    img_data.save('/tmp/test.png')
    with open('/tmp/test.png') as f:
        p = f.read()
        media_id = upload_media(auth, p)
    print 'uploaded media'
    endpoint = 'statuses/update.json'
    params = {"status":"@"+screen_name + " secret!", "media_ids":media_id}
    r = requests.post(api_url+endpoint, params=params, auth=auth)
    print r.status_code
    
def get_tweets(auth):
    endpoint = 'statuses/mentions_timeline.json'
    params = {"count":5, "contributor_details":True}
    r = requests.get(api_url+ endpoint, params=params, auth=auth)
    for i in json.loads(r.text):
        if 'secret' in i["text"]:
            #get image
            for u in  i["entities"]["media"]:
                print u["media_url_https"]
                message = stepic.decode(get_Image_from_url( u["media_url_https"]+':large'))
                print private_key.decrypt(message)


if __name__ == '__main__':
    user = raw_input('please enter your username:\n')
    auth = load_user(user)
    user_input = raw_input('''what would you like to do?
            1. Create a new Key
            2. Securely tweet a friend
            3. Start a new Group chat
            4. Do more Group Chat stuff
            0. Quit
            ''')
    #session.request(method, url, data=data, params=params, timeout=5, files=files)
    endpoint = 'statuses/update.json'
    params = {"status": 'this is a test!'} 
    r = requests.post(api_url+endpoint, params=params, auth=auth)
    print r.text
    #create_key(auth)
    message = 'this is a test'
    tweet_friend(auth, '69inthesunshine', message)
    get_tweets(auth)
    
    print user_input
    #while user_input is not '0':
