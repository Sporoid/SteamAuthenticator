#!/usr/bin/env python3
import os
import time
import hmac
import json
import struct
import base64
import requests
from hashlib import sha1

symbols = '23456789BCDFGHJKMNPQRTVWXY'

def getQueryTime():
    try:
        request = requests.post('https://api.steampowered.com/ITwoFactorService/QueryTime/v0001', timeout=30)
        json_data = request.json()
        server_time = int(json_data['response']['server_time']) - time.time()
        return server_time
    except:
        return 0

def getGuardCode(shared_secret):
    code = ''
    timestamp = time.time() + getQueryTime()
    _hmac = hmac.new(base64.b64decode(shared_secret), struct.pack('>Q', int(timestamp/30)), sha1).digest()
    _ord = ord(_hmac[19:20]) & 0xF
    value = struct.unpack('>I', _hmac[_ord:_ord+4])[0] & 0x7fffffff
    for i in range(5):
        code += symbols[value % len(symbols)]
        value = int(value / len(symbols))
    return code

def is_token_expired(token):
    try:
        token_parts = token.split('.')
        if len(token_parts) < 2:
            return True
        
        payload = token_parts[1]
        payload = payload.replace('-', '+').replace('_', '/')
        
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        
        payload_bytes = base64.b64decode(payload)
        payload_data = json.loads(payload_bytes.decode('utf-8'))
        
        exp_time = payload_data.get('exp', 0)
        current_time = int(time.time())
        
        return current_time > exp_time
    except:
        return True

def steam_login_with_tokens(username, password, shared_secret):
    try:
        import rsa
        
        session = requests.Session()
        
        rsa_response = session.get(
            'https://api.steampowered.com/IAuthenticationService/GetPasswordRSAPublicKey/v1/',
            params={'account_name': username},
            timeout=30
        )
        
        if rsa_response.status_code != 200:
            return None, None
        
        rsa_data = rsa_response.json()
        rsa_mod = int(rsa_data['response']['publickey_mod'], 16)
        rsa_exp = int(rsa_data['response']['publickey_exp'], 16)
        rsa_timestamp = rsa_data['response']['timestamp']
        
        public_key = rsa.PublicKey(rsa_mod, rsa_exp)
        encrypted_password = rsa.encrypt(password.encode('utf-8'), public_key)
        encrypted_password_b64 = base64.b64encode(encrypted_password).decode('utf-8')
        
        begin_auth_data = {
            'account_name': username,
            'encrypted_password': encrypted_password_b64,
            'encryption_timestamp': rsa_timestamp,
            'remember_login': 'false',
            'platform_type': '2',
            'persistence': '1',
            'website_id': 'Mobile'
        }
        
        begin_response = session.post(
            'https://api.steampowered.com/IAuthenticationService/BeginAuthSessionViaCredentials/v1/',
            data=begin_auth_data,
            timeout=30
        )
        
        if begin_response.status_code != 200:
            return None, None
        
        begin_result = begin_response.json()
        
        if 'response' not in begin_result:
            return None, None
        
        response_data = begin_result['response']
        client_id = response_data.get('client_id')
        request_id = response_data.get('request_id')
        allowed_confirmations = response_data.get('allowed_confirmations', [])
        
        if not client_id or not request_id:
            return None, None
        
        needs_twofactor = any(c.get('confirmation_type') == 3 for c in allowed_confirmations)
        
        if needs_twofactor:
            code = getGuardCode(shared_secret)
            
            update_data = {
                'client_id': client_id,
                'steamid': response_data.get('steamid'),
                'code': code,
                'code_type': '3'
            }
            
            update_response = session.post(
                'https://api.steampowered.com/IAuthenticationService/UpdateAuthSessionWithSteamGuardCode/v1/',
                data=update_data,
                timeout=30
            )
            
            if update_response.status_code != 200:
                return None, None
        
        for attempt in range(30):
            time.sleep(1)
            
            poll_data = {
                'client_id': client_id,
                'request_id': request_id
            }
            
            poll_response = session.post(
                'https://api.steampowered.com/IAuthenticationService/PollAuthSessionStatus/v1/',
                data=poll_data,
                timeout=30
            )
            
            if poll_response.status_code != 200:
                continue
            
            poll_result = poll_response.json()
            
            if 'response' not in poll_result:
                continue
            
            tokens = poll_result['response']
            access_token = tokens.get('access_token')
            refresh_token = tokens.get('refresh_token')
            
            if access_token and refresh_token:
                return access_token, refresh_token
        
        return None, None
    except Exception as e:
        print(f"Exception: {e}")
        return None, None

# Credentials
credentials_map = {
    'account 1': ('username', 'password'),
    'account 2': ('username', 'password')
}

script_dir = os.path.dirname(os.path.abspath(__file__))
mafiles_dir = os.path.join(script_dir, 'maFiles')

print("="*60)
print("Refreshing All Accounts")
print("="*60)

success_count = 0
fail_count = 0

with os.scandir(mafiles_dir) as files:
    for file in files:
        if file.is_file() and file.name.endswith('.maFile'):
            with open(file, 'r') as f:
                mafile_data = json.loads(f.read())
                account_name = mafile_data['account_name']
                
                # Check if token is expired
                access_token = mafile_data['Session']['AccessToken']
                if not is_token_expired(access_token):
                    print(f"\n✓ {account_name}: Token is still valid")
                    success_count += 1
                    continue
                
                print(f"\n⟳ {account_name}: Refreshing expired token...")
                
                if account_name not in credentials_map:
                    print(f"  ✗ No credentials found")
                    fail_count += 1
                    continue
                
                username, password = credentials_map[account_name]
                shared_secret = mafile_data['shared_secret']
                
                new_access_token, new_refresh_token = steam_login_with_tokens(username, password, shared_secret)
                
                if new_access_token and new_refresh_token:
                    mafile_data['Session']['AccessToken'] = new_access_token
                    mafile_data['Session']['RefreshToken'] = new_refresh_token
                    
                    with open(file.path, 'w') as fw:
                        json.dump(mafile_data, fw)
                    
                    print(f"  ✓ Token refreshed successfully")
                    success_count += 1
                else:
                    print(f"  ✗ Failed to refresh token")
                    fail_count += 1

print(f"\n{'='*60}")
print(f"Summary: {success_count} successful, {fail_count} failed")
print(f"{'='*60}\n")

