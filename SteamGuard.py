import os
import time
import hmac
import json
import struct
import base64
import requests
from hashlib import sha1
import platform
import urllib.parse
import select
import sys
import secrets

BAR_LEN = 37
elements = ['-', '\\', '|', '/']

# Global variable to cache Steam time offset
_steam_time_offset = None
_last_time_sync = 0

def getQueryTime():
    """Get Steam server time offset and cache it"""
    global _steam_time_offset, _last_time_sync
    
    current_time = time.time()
    
    # Resync every 5 minutes or if not set
    if _steam_time_offset is None or (current_time - _last_time_sync) > 300:
        try:
            request = requests.post('https://api.steampowered.com/ITwoFactorService/QueryTime/v0001', timeout=30)
            json_data = request.json()
            server_time = int(json_data['response']['server_time'])
            _steam_time_offset = server_time - current_time
            _last_time_sync = current_time
            print(f"[Synced with Steam] Offset: {_steam_time_offset:.2f}s")
        except:
            if _steam_time_offset is None:
                _steam_time_offset = 0
    
    return _steam_time_offset


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


def generate_device_id(steamid):
    hexed_steam_id = sha1(str(steamid).encode('ascii')).hexdigest()
    return f"android:{hexed_steam_id[:8]}-{hexed_steam_id[8:12]}-{hexed_steam_id[12:16]}-{hexed_steam_id[16:20]}-{hexed_steam_id[20:32]}"


def generate_confirmation_key(identity_secret, tag, timestamp=None):
    if timestamp is None:
        timestamp = int(time.time())
    
    buffer = struct.pack('>Q', timestamp) + tag.encode('ascii')
    _hmac = hmac.new(base64.b64decode(identity_secret), buffer, sha1).digest()
    return base64.b64encode(_hmac).decode('ascii')


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
        return None, None


def refresh_access_token(mafile_data, credentials=None):
    try:
        refresh_token = mafile_data['Session']['RefreshToken']
        steamid = mafile_data['Session']['SteamID']
        
        if is_token_expired(refresh_token):
            if credentials:
                username, password = credentials
                shared_secret = mafile_data['shared_secret']
                access_token, refresh_token = steam_login_with_tokens(username, password, shared_secret)
                if access_token and refresh_token:
                    mafile_data['Session']['AccessToken'] = access_token
                    mafile_data['Session']['RefreshToken'] = refresh_token
                    return access_token
            return None
        
        data = {
            'refresh_token': refresh_token,
            'steamid': str(steamid)
        }
        
        response = requests.post(
            'https://api.steampowered.com/IAuthenticationService/GenerateAccessTokenForApp/v1/',
            data=data,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            new_access_token = result.get('response', {}).get('access_token')
            if new_access_token:
                mafile_data['Session']['AccessToken'] = new_access_token
                return new_access_token
        return None
    except:
        return None


def save_mafile(mafile_path, mafile_data):
    try:
        with open(mafile_path, 'w') as f:
            json.dump(mafile_data, f)
        return True
    except:
        return False


def generate_session_id():
    return secrets.token_hex(16)


def get_cookies(steamid, access_token, session_id=None):
    if session_id is None:
        session_id = generate_session_id()
    
    steam_login_secure = f"{steamid}%7C%7C{access_token}"
    
    cookies = {
        'steamLoginSecure': steam_login_secure,
        'sessionid': session_id,
        'mobileClient': 'android',
        'mobileClientVersion': '777777 3.6.1'
    }
    return cookies


def get_confirmations(mafile_data):
    try:
        timestamp = int(time.time())
        identity_secret = mafile_data['identity_secret']
        steamid = mafile_data['Session']['SteamID']
        access_token = mafile_data['Session']['AccessToken']
        device_id = mafile_data.get('device_id', generate_device_id(steamid))
        
        conf_key = generate_confirmation_key(identity_secret, 'conf', timestamp)
        
        params = {
            'p': device_id,
            'a': steamid,
            'k': conf_key,
            't': timestamp,
            'm': 'react',
            'tag': 'conf'
        }
        
        headers = {
            'User-Agent': 'okhttp/3.12.12'
        }
        
        cookies = get_cookies(steamid, access_token)
        
        url = f"https://steamcommunity.com/mobileconf/getlist?{urllib.parse.urlencode(params)}"
        response = requests.get(url, headers=headers, cookies=cookies, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                confirmations = data.get('conf', [])
                for conf in confirmations:
                    conf['_timestamp'] = timestamp
                    conf['_device_id'] = device_id
                return confirmations
        return []
    except:
        return []


def send_confirmation(mafile_data, conf_id, conf_key, operation='allow'):
    try:
        timestamp = int(time.time())
        identity_secret = mafile_data['identity_secret']
        steamid = mafile_data['Session']['SteamID']
        access_token = mafile_data['Session']['AccessToken']
        device_id = mafile_data.get('device_id', generate_device_id(steamid))
        
        tag = 'accept' if operation == 'allow' else 'reject'
        conf_key_generated = generate_confirmation_key(identity_secret, tag, timestamp)
        
        params = {
            'op': operation,
            'p': device_id,
            'a': steamid,
            'k': conf_key_generated,
            't': timestamp,
            'm': 'react',
            'tag': tag,
            'cid': conf_id,
            'ck': conf_key
        }
        
        headers = {
            'User-Agent': 'okhttp/3.12.12'
        }
        
        cookies = get_cookies(steamid, access_token)
        
        url = f"https://steamcommunity.com/mobileconf/ajaxop?{urllib.parse.urlencode(params)}"
        response = requests.get(url, headers=headers, cookies=cookies, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            return data.get('success', False)
        return False
    except:
        return False


def verification_mode():
    clear_console()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    mafiles_dir = os.path.join(script_dir, 'maFiles')
    
    credentials_map = {
        'xkce27': ('xkce27', 'ymw@ntz3xau2gtk-VCT'),
        'juanpi1588': ('juanpi1588', 'EHD_xtx-cnc0drw0wgp'),
        'trikce': ('trikce', 'eqb6UYR5hxa1pvc-qna')
    }
    
    all_confirmations = []
    account_confirmations = {}
    
    with os.scandir(mafiles_dir) as files:
        for file in files:
            if file.is_file() and file.name.endswith('.maFile'):
                file_path = file.path
                with open(file, 'r') as f:
                    data = json.loads(f.read())
                    account_name = data['account_name']
                    
                    access_token = data['Session']['AccessToken']
                    if is_token_expired(access_token):
                        print(f"Token expired for {account_name}, refreshing...")
                        credentials = credentials_map.get(account_name)
                        if credentials:
                            new_token = refresh_access_token(data, credentials)
                            if new_token:
                                print(f"✓ Token refreshed for {account_name}")
                                save_mafile(file_path, data)
                            else:
                                print(f"✗ Failed to refresh token for {account_name}")
                                continue
                        else:
                            print(f"✗ No credentials found for {account_name}")
                            continue
                    
                    confirmations = get_confirmations(data)
                    if confirmations:
                        account_confirmations[account_name] = {
                            'data': data,
                            'confirmations': confirmations
                        }
                        all_confirmations.extend(confirmations)
    
    if not all_confirmations:
        print("No pending confirmations.\n")
        input("Press Enter to return...")
        return
    
    print("=" * 60)
    print(f"PENDING CONFIRMATIONS: {len(all_confirmations)}")
    print("=" * 60)
    
    conf_types = {
        1: 'Test',
        2: 'Trade',
        3: 'Market Listing',
        4: 'Feature Opt-Out',
        5: 'Phone Number Change',
        6: 'Account Recovery'
    }
    
    index = 1
    confirmation_map = {}
    for account_name, info in account_confirmations.items():
        for conf in info['confirmations']:
            conf_type = conf_types.get(conf.get('type', 0), 'Unknown')
            headline = conf.get('headline', 'Unknown')
            summary_lines = conf.get('summary', ['No description'])
            creator = conf.get('creator_id', 'N/A')
            
            # Calculate verification code (last 5 digits of creator ID)
            verification_code = str(creator)[-5:] if creator != 'N/A' else 'N/A'
            
            print(f"{index}. [{account_name}] {headline}")
            if creator != 'N/A':
                print(f"   Creator ID: {creator}")
                print(f"   Verification Code: [{verification_code}]")
            
            for line in summary_lines[:3]:
                if line:
                    print(f"   {line}")
            
            print()
            
            confirmation_map[index] = {
                'account': account_name,
                'conf': conf,
                'data': info['data']
            }
            index += 1
    
    print("=" * 60)
    print("SELECT ACTION:")
    print("=" * 60)
    print("[Number] - Select confirmation")
    print("[A]      - Approve All")
    print("[D]      - Deny All")
    print("[Q]      - Quit")
    print("=" * 60)
    
    choice = input("\nYour choice: ").strip().lower()
    
    if choice == 'a':
        clear_console()
        print("\n" + "!" * 60)
        print("WARNING: You are about to APPROVE ALL confirmations!")
        print("This action cannot be undone.")
        print("!" * 60)
        confirm = input("\nPress 1 to CONFIRM, 2 to CANCEL: ").strip()
        
        if confirm == '1':
            clear_console()
            print("\nApproving all confirmations...\n")
            for idx, item in confirmation_map.items():
                conf = item['conf']
                conf_type = conf_types.get(conf.get('type', 0), 'Unknown')
                result = send_confirmation(
                    item['data'],
                    conf['id'],
                    conf['nonce'],
                    'allow'
                )
                status = "✓" if result else "✗"
                print(f"{status} [{item['account']}] {conf.get('headline', 'Unknown')} ({conf_type})")
            input("\nPress Enter to return...")
        else:
            clear_console()
            print("\nCancelled.")
            input("Press Enter to return...")
    elif choice == 'd':
        clear_console()
        print("\n" + "!" * 60)
        print("WARNING: You are about to DENY ALL confirmations!")
        print("This action cannot be undone.")
        print("!" * 60)
        confirm = input("\nPress 1 to CONFIRM, 2 to CANCEL: ").strip()
        
        if confirm == '1':
            clear_console()
            print("\nDenying all confirmations...\n")
            for idx, item in confirmation_map.items():
                conf = item['conf']
                conf_type = conf_types.get(conf.get('type', 0), 'Unknown')
                result = send_confirmation(
                    item['data'],
                    conf['id'],
                    conf['nonce'],
                    'cancel'
                )
                status = "✓" if result else "✗"
                print(f"{status} [{item['account']}] {conf.get('headline', 'Unknown')} ({conf_type})")
            input("\nPress Enter to return...")
        else:
            clear_console()
            print("\nCancelled.")
            input("Press Enter to return...")
    elif choice == 'q':
        return
    elif choice.isdigit():
        idx = int(choice)
        if idx in confirmation_map:
            clear_console()
            item = confirmation_map[idx]
            conf = item['conf']
            conf_type = conf_types.get(conf.get('type', 0), 'Unknown')
            headline = conf.get('headline', 'Unknown')
            
            print("\n" + "=" * 60)
            print(f"SELECTED: [{item['account']}] {headline}")
            print("=" * 60)
            print("\nACTION:")
            print("[1] - APPROVE")
            print("[2] - DENY")
            print("[Q] - Cancel")
            print("=" * 60)
            
            action = input("\nYour choice: ").strip().lower()
            
            if action == '1':
                print(f"\nApproving...")
                result = send_confirmation(
                    item['data'],
                    conf['id'],
                    conf['nonce'],
                    'allow'
                )
                if result:
                    print(f"✓ Successfully approved!")
                else:
                    print(f"✗ Failed to approve - please try again")
                input("\nPress Enter to return...")
            elif action == '2':
                print(f"\nDenying...")
                result = send_confirmation(
                    item['data'],
                    conf['id'],
                    conf['nonce'],
                    'cancel'
                )
                if result:
                    print(f"✓ Successfully denied!")
                else:
                    print(f"✗ Failed to deny - please try again")
                input("\nPress Enter to return...")
            else:
                clear_console()
                print("\nCancelled.")
                input("Press Enter to return...")
        else:
            clear_console()
            print("\nInvalid number")
            input("Press Enter to return...")
    else:
        clear_console()
        print("\nInvalid choice")
        input("Press Enter to return...")


def get_time_remaining():
    """Get seconds remaining until next TOTP code"""
    current_time = int(time.time() + getQueryTime())
    return 30 - (current_time % 30)


def draw_progress_bar(seconds_remaining, total_seconds=30, width=30):
    """Draw a clean progress bar"""
    filled = int(((total_seconds - seconds_remaining) / total_seconds) * width)
    bar = '█' * filled + '░' * (width - filled)
    return bar


def add_new_account():
    """Launch add_account.py script"""
    import subprocess
    script_dir = os.path.dirname(os.path.abspath(__file__))
    add_account_script = os.path.join(script_dir, 'add_account.py')
    
    if os.path.exists(add_account_script):
        try:
            subprocess.run([sys.executable, add_account_script])
        except Exception as e:
            print(f"Error launching add_account.py: {e}")
            input("Press Enter to continue...")
    else:
        print("Error: add_account.py not found")
        input("Press Enter to continue...")

def run_code():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    mafiles_dir = os.path.join(script_dir, 'maFiles')
    
    # Check if maFiles directory exists
    if not os.path.exists(mafiles_dir):
        os.makedirs(mafiles_dir)
    
    # Check if directory is empty
    mafiles_list = [f for f in os.listdir(mafiles_dir) if f.endswith('.maFile')]
    
    if not mafiles_list:
        clear_console()
        print("=" * 60)
        print("NO ACCOUNTS FOUND")
        print("=" * 60)
        print("\nNo Steam Guard accounts have been set up yet.")
        print("\nWould you like to add a new account now?")
        print("=" * 60)
        
        choice = input("\nAdd new account? (yes/no): ").strip().lower()
        if not choice or choice in ['yes', 'y']:
            add_new_account()
            # Reload after adding account
            mafiles_list = [f for f in os.listdir(mafiles_dir) if f.endswith('.maFile')]
            if not mafiles_list:
                print("\nNo accounts were added. Exiting...")
                return
        else:
            print("\nExiting...")
            return

    # Load all accounts
    accounts = []
    with os.scandir(mafiles_dir) as files:
        for file in files:
            if file.is_file() and file.name.endswith('.maFile'):
                with open(file, 'r') as f:
                    data = json.loads(f.read())
                    accounts.append({
                        'name': data['account_name'],
                        'steamid': data['Session']['SteamID'],
                        'secret': data['shared_secret']
                    })

    if not accounts:
        print("No valid accounts found")
        return

    # Initial sync with Steam
    print("\n[Syncing with Steam...]")
    getQueryTime()
    
    last_code_time = 0
    last_display_time = 0
    
    while True:
        current_time = time.time()
        time_remaining = get_time_remaining()
        current_code_time = (int(time.time() + getQueryTime()) // 30)
        
        # Regenerate codes if new cycle
        if current_code_time != last_code_time:
            for account in accounts:
                account['code'] = getGuardCode(account['secret'])
            last_code_time = current_code_time
        
        # Update display every second
        if current_time - last_display_time >= 1.0:
            clear_console()
            
            print("=" * 60)
            print("STEAM GUARD AUTHENTICATOR")
            print("=" * 60)
            print("\nPress 'Ctrl+C' to stop | Type '2' for new account | Type '3' for confirmations\n")
            
            # Display each account
            for account in accounts:
                code = account.get('code', getGuardCode(account['secret']))
                bar = draw_progress_bar(time_remaining)
                
                print(f"Username: {account['name']}")
                print(f"SteamId: {account['steamid']}")
                print(f"GuardCode: {code}  [{bar}] {time_remaining}s")
                print()
            
            print("\n> ", end='', flush=True)
            
            last_display_time = current_time
        
        # Check for user input (non-blocking)
        if platform.system() != 'Windows':
            readable, _, _ = select.select([sys.stdin], [], [], 0.1)
            if readable:
                user_input = sys.stdin.readline().strip()
                if user_input == '2':
                    print("[Launching add account...]")
                    add_new_account()
                    # Reload accounts after adding
                    accounts = []
                    with os.scandir(mafiles_dir) as files:
                        for file in files:
                            if file.is_file() and file.name.endswith('.maFile'):
                                with open(file, 'r') as f:
                                    data = json.loads(f.read())
                                    accounts.append({
                                        'name': data['account_name'],
                                        'steamid': data['Session']['SteamID'],
                                        'secret': data['shared_secret']
                                    })
                    last_display_time = 0  # Force immediate redraw
                elif user_input == '3':
                    print("[Loading confirmations...]")
                    verification_mode()
                    last_display_time = 0  # Force immediate redraw
        else:
            time.sleep(0.1)


def clear_console():
    # Clear the console based on the operating system
    if platform.system() == 'Windows':
        os.system('cls')
    else:
        os.system('clear')


symbols = '23456789BCDFGHJKMNPQRTVWXY'

# Initial clear only
clear_console()

try:
    run_code()
except KeyboardInterrupt:
    print("\n\nExiting...")
    pass
