#!/usr/bin/env python3
import os
import json
import time
import hmac
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

def generate_device_id(steamid):
    hexed_steam_id = sha1(str(steamid).encode('ascii')).hexdigest()
    return f"android:{hexed_steam_id[:8]}-{hexed_steam_id[8:12]}-{hexed_steam_id[12:16]}-{hexed_steam_id[16:20]}-{hexed_steam_id[20:32]}"

def add_authenticator(username, password):
    try:
        import rsa
        
        session = requests.Session()
        
        print(f"\n[1/5] Getting RSA key...")
        rsa_response = session.get(
            'https://api.steampowered.com/IAuthenticationService/GetPasswordRSAPublicKey/v1/',
            params={'account_name': username},
            timeout=30
        )
        
        if rsa_response.status_code != 200:
            print("Failed to get RSA key")
            return None
        
        rsa_data = rsa_response.json()
        rsa_mod = int(rsa_data['response']['publickey_mod'], 16)
        rsa_exp = int(rsa_data['response']['publickey_exp'], 16)
        rsa_timestamp = rsa_data['response']['timestamp']
        
        public_key = rsa.PublicKey(rsa_mod, rsa_exp)
        encrypted_password = rsa.encrypt(password.encode('utf-8'), public_key)
        encrypted_password_b64 = base64.b64encode(encrypted_password).decode('utf-8')
        
        print(f"[2/5] Beginning authentication session...")
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
            print("Failed to begin authentication")
            return None
        
        begin_result = begin_response.json()
        
        if 'response' not in begin_result:
            print("Invalid response from authentication")
            return None
        
        response_data = begin_result['response']
        client_id = response_data.get('client_id')
        request_id = response_data.get('request_id')
        steamid = response_data.get('steamid')
        allowed_confirmations = response_data.get('allowed_confirmations', [])
        
        if not client_id or not request_id or not steamid:
            print("Missing required authentication data")
            return None
        
        print(f"\nSteamID: {steamid}")
        print(f"Client ID: {client_id}")
        
        print(f"\n[3/6] Checking authentication requirements...")
        print(f"Allowed confirmations: {allowed_confirmations}")
        
        needs_email = any(c.get('confirmation_type') == 2 for c in allowed_confirmations)
        needs_device = any(c.get('confirmation_type') == 3 for c in allowed_confirmations)
        
        if needs_device:
            print("\nERROR: This account already has a mobile authenticator!")
            print("You cannot add a new authenticator while one is already active.")
            print("\nTo proceed, you must first remove the existing authenticator:")
            print("  1. Go to: https://store.steampowered.com/twofactor/manage")
            print("  2. Click 'Remove Authenticator'")
            print("  3. Enter your revocation code")
            print("\nThen try running this script again.")
            return None
        
        if needs_email:
            email_domain = None
            for conf in allowed_confirmations:
                if conf.get('confirmation_type') == 2:
                    email_domain = conf.get('associated_message', 'your email')
                    break
            
            print(f"\n{'='*60}")
            print("ERROR: EMAIL STEAM GUARD IS ENABLED")
            print(f"{'='*60}")
            print(f"\nYour account has Steam Guard via Email enabled.")
            print(f"Email: {email_domain}")
            print("\nYou CANNOT have both Email Steam Guard and Mobile Authenticator.")
            print("You must disable Email Steam Guard first.")
            print(f"\n{'='*60}")
            print("HOW TO DISABLE EMAIL STEAM GUARD:")
            print(f"{'='*60}")
            print("\n1. Open your web browser and go to:")
            print("   https://store.steampowered.com/twofactor/manage")
            print("\n2. Log in to your Steam account if needed")
            print("\n3. Look for the section:")
            print("   'Confirmación de inicio de sesión' or 'Login Confirmation'")
            print("\n4. Find the option:")
            print("   'Eliminar método de seguridad' or 'Remove Security Method'")
            print("\n5. Click it to disable Email Steam Guard")
            print("\n6. Confirm the removal")
            print("\n7. Once disabled, run this script again")
            print(f"\n{'='*60}")
            print("IMPORTANT NOTES:")
            print(f"{'='*60}")
            print("- Your account will be temporarily less secure")
            print("- This is normal - you're replacing Email Guard with Mobile Auth")
            print("- Mobile Authenticator is MORE secure than Email Guard")
            print("- After setup, you'll have stronger 2FA protection")
            print(f"{'='*60}")
            
            choice = input("\nHave you disabled Email Steam Guard? (yes/no): ").strip().lower()
            
            if choice and choice not in ['yes', 'y']:
                print("\n" + "="*60)
                print("Please disable Email Steam Guard first, then run this script again.")
                print("\nQuick link: https://store.steampowered.com/twofactor/manage")
                print("="*60)
                return None
            
            print("\nProceeding with setup...")
            print("Note: If you still see errors, Email Guard may still be active.")
            print("Wait a few minutes after disabling it, then try again.")
            
            print(f"\nAttempting to proceed with email verification...")
            print(f"Requesting Steam to send email code to: {email_domain}")
            
            # Try to request the email code by updating with a dummy code
            # This should trigger Steam to send the actual email
            try:
                print("Triggering email code request...")
                trigger_response = session.post(
                    'https://api.steampowered.com/IAuthenticationService/UpdateAuthSessionWithSteamGuardCode/v1/',
                    data={
                        'client_id': client_id,
                        'steamid': steamid,
                        'code': '',  # Empty code to trigger email
                        'code_type': '2'
                    },
                    timeout=30
                )
                if trigger_response.status_code == 200:
                    print("Email code request sent!")
                else:
                    print(f"Note: Trigger returned status {trigger_response.status_code}")
            except Exception as e:
                print(f"Note: Could not trigger email: {e}")
            
            # Try polling first to see if we can proceed without email
            print("\nChecking if email code is actually required...")
            access_token_early = None
            for quick_attempt in range(3):
                time.sleep(1)
                try:
                    quick_poll = session.post(
                        'https://api.steampowered.com/IAuthenticationService/PollAuthSessionStatus/v1/',
                        data={'client_id': client_id, 'request_id': request_id},
                        timeout=30
                    )
                    if quick_poll.status_code == 200:
                        result = quick_poll.json()
                        if 'response' in result:
                            access_token_early = result['response'].get('access_token')
                            if access_token_early:
                                print("\nSuccess! Access token obtained without email code.")
                                print("(Steam allowed it - possibly trusted device)")
                                access_token = access_token_early
                                break
                except:
                    pass
            
            if not access_token_early:
                print("\nEmail code is required. Waiting for email...")
                print("(Check your inbox and spam/junk folder)")
                
                email_code = None
                max_email_attempts = 3
                
                for attempt in range(max_email_attempts):
                    if attempt > 0:
                        print(f"\nAttempt {attempt + 1} of {max_email_attempts}")
                    
                    email_code = input("\nEnter the code from your email (or 'skip' to try without): ").strip()
                    
                    if email_code.lower() == 'skip':
                        print("\nTrying to proceed without email code...")
                        break
                    
                    if not email_code:
                        print("Email code is required (or type 'skip')")
                        if attempt < max_email_attempts - 1:
                            continue
                        break
                    
                    if len(email_code) < 5:
                        print("Email code seems too short. Please check and try again.")
                        if attempt < max_email_attempts - 1:
                            continue
                    
                    print("\nSubmitting email code...")
                    
                    update_email_data = {
                        'client_id': client_id,
                        'steamid': steamid,
                        'code': email_code,
                        'code_type': '2'
                    }
                    
                    update_email_response = session.post(
                        'https://api.steampowered.com/IAuthenticationService/UpdateAuthSessionWithSteamGuardCode/v1/',
                        data=update_email_data,
                        timeout=30
                    )
                    
                    if update_email_response.status_code == 200:
                        print("Email code submitted successfully!")
                        break
                    else:
                        print(f"Failed to submit email code (HTTP {update_email_response.status_code})")
                        if attempt < max_email_attempts - 1:
                            print("Please try again...")
                            continue
        else:
            print("No email confirmation needed.")
        
        print(f"\n[4/6] Obtaining access token...")
        if needs_email:
            print("Waiting for email confirmation (up to 60 seconds)...")
        else:
            print("Polling Steam servers (this may take up to 30 seconds)...")
        
        access_token = None
        max_attempts = 60 if needs_email else 30
        
        for attempt in range(max_attempts):
            if attempt > 0 and attempt % 10 == 0:
                print(f"Still waiting... ({attempt}/{max_attempts} seconds)")
                if needs_email and attempt == 20:
                    print("Tip: Make sure you clicked the link in the Steam email!")
            
            time.sleep(1)
            
            poll_data = {
                'client_id': client_id,
                'request_id': request_id
            }
            
            try:
                poll_response = session.post(
                    'https://api.steampowered.com/IAuthenticationService/PollAuthSessionStatus/v1/',
                    data=poll_data,
                    timeout=30
                )
                
                if poll_response.status_code != 200:
                    if attempt == 0:
                        print(f"Warning: Poll returned status {poll_response.status_code}")
                    continue
                
                poll_result = poll_response.json()
                
                if 'response' not in poll_result:
                    continue
                
                tokens = poll_result['response']
                access_token = tokens.get('access_token')
                
                if access_token:
                    print("\nAccess token obtained successfully!")
                    break
                    
                if attempt == 0 and tokens:
                    print(f"Response keys: {list(tokens.keys())}")
                    
            except Exception as e:
                if attempt == 0:
                    print(f"Error during polling: {e}")
                continue
        
        if not access_token:
            print("\n" + "="*60)
            print("FAILED TO OBTAIN ACCESS TOKEN")
            print("="*60)
            print("\nThis usually means:")
            if needs_email:
                print("  - Email confirmation was not completed")
                print("  - Check your email (including spam folder)")
                print("  - The confirmation link may have expired")
            else:
                print("  - Login session expired")
                print("  - Account requires additional verification")
                print("  - Incorrect username or password")
            print("\nTroubleshooting:")
            print("  1. Make sure your Steam credentials are correct")
            print("  2. Check if your account has Steam Guard enabled")
            print("  3. Try logging into Steam website to verify account status")
            print("  4. Wait a few minutes and try again")
            print("="*60)
            return None
        
        print(f"[5/6] Adding authenticator to account...")
        
        add_auth_response = session.post(
            'https://api.steampowered.com/ITwoFactorService/AddAuthenticator/v1/',
            data={
                'steamid': steamid,
                'authenticator_type': '1',
                'device_identifier': generate_device_id(steamid),
                'sms_phone_id': '1',
                'access_token': access_token
            },
            timeout=30
        )
        
        if add_auth_response.status_code != 200:
            print(f"Failed to add authenticator (HTTP {add_auth_response.status_code})")
            return None
        
        auth_data = add_auth_response.json()
        
        if 'response' not in auth_data:
            print("Invalid authenticator response")
            return None
        
        auth_response = auth_data['response']
        
        status = auth_response.get('status', 0)
        
        if status == 29:
            print("\nError: Account already has an authenticator linked.")
            print("You must remove the existing authenticator before adding a new one.")
            print("Visit: https://store.steampowered.com/twofactor/manage")
            return None
        elif status == 2:
            print("\nError: Phone number issue.")
            print("Your account may need a phone number added.")
            print("Visit: https://store.steampowered.com/phone/add")
            return None
        elif status == 84:
            print("\nError: Rate limit exceeded.")
            print("Please wait a few minutes before trying again.")
            return None
        elif status != 1:
            print(f"\nFailed to add authenticator. Status code: {status}")
            return None
        
        shared_secret = auth_response.get('shared_secret')
        identity_secret = auth_response.get('identity_secret')
        revocation_code = auth_response.get('revocation_code')
        uri = auth_response.get('uri')
        server_time = auth_response.get('server_time')
        account_name = auth_response.get('account_name', username)
        token_gid = auth_response.get('token_gid')
        secret_1 = auth_response.get('secret_1')
        
        if not shared_secret or not identity_secret:
            print("Missing secrets in response")
            return None
        
        print(f"\n{'='*60}")
        print("CRITICAL: WRITE DOWN YOUR REVOCATION CODE NOW!")
        print(f"Revocation Code: {revocation_code}")
        print(f"{'='*60}")
        print("\nYou will need this code if you lose access to your authenticator.")
        print("Without it, you may lose access to your Steam account permanently!")
        print(f"{'='*60}\n")
        
        input("Press Enter after you have written down the revocation code...")
        
        print(f"[6/7] Verifying you saved the revocation code...")
        print("\nTo ensure you saved it correctly, please re-enter the revocation code:")
        verify_code = input("Enter revocation code: ").strip().upper()
        
        if verify_code != revocation_code:
            print("\nERROR: Revocation code does not match!")
            print("The authenticator has NOT been linked to protect your account.")
            print(f"The correct code was: {revocation_code}")
            print("\nPlease write it down and try again.")
            return None
        
        print("\nRevocation code verified successfully!")
        
        print(f"\n[7/7] SMS code verification...")
        print("\nCheck your phone for the SMS code from Steam.")
        
        max_sms_attempts = 3
        for attempt in range(max_sms_attempts):
            if attempt > 0:
                print(f"\nAttempt {attempt + 1} of {max_sms_attempts}")
            
            sms_code = input("Enter SMS code: ").strip()
            
            if not sms_code:
                print("SMS code is required")
                if attempt < max_sms_attempts - 1:
                    continue
                return None
            
            if not sms_code.isalnum():
                print("SMS code should only contain letters and numbers")
                if attempt < max_sms_attempts - 1:
                    continue
                return None
            
            break
        else:
            print("\nToo many failed attempts")
            return None
        
        finalize_success = False
        finalize_attempts = 3
        
        for attempt in range(finalize_attempts):
            if attempt > 0:
                print(f"\nAttempt {attempt + 1} of {finalize_attempts}")
                print("Check your phone for the SMS code from Steam.")
                sms_code = input("Enter SMS code: ").strip()
                
                if not sms_code:
                    print("SMS code is required")
                    continue
            
            # Get current server time
            current_time = int(time.time())
            
            finalize_response = session.post(
                'https://api.steampowered.com/ITwoFactorService/FinalizeAddAuthenticator/v1/',
                data={
                    'steamid': steamid,
                    'authenticator_code': getGuardCode(shared_secret),
                    'authenticator_time': current_time,
                    'activation_code': sms_code,
                    'access_token': access_token
                },
                timeout=30
            )
            
            if finalize_response.status_code != 200:
                print(f"Failed to finalize authenticator (HTTP {finalize_response.status_code})")
                if attempt < finalize_attempts - 1:
                    continue
                return None
            
            finalize_data = finalize_response.json()
            
            if 'response' not in finalize_data:
                print("Invalid finalization response")
                if attempt < finalize_attempts - 1:
                    continue
                return None
            
            finalize_result = finalize_data['response']
            
            if finalize_result.get('success'):
                finalize_success = True
                break
            else:
                status = finalize_result.get('status', 'unknown')
                if status == 89:
                    print("Error: Invalid SMS code. Please try again.")
                elif status == 2:
                    print("Error: Authenticator already finalized or invalid state")
                    return None
                else:
                    print(f"Failed to finalize authenticator. Status: {status}")
                
                if attempt < finalize_attempts - 1:
                    continue
                return None
        
        if not finalize_success:
            print("\nFailed to finalize authenticator after multiple attempts.")
            print(f"IMPORTANT: Your revocation code is: {revocation_code}")
            print("Save this code! You may need it to remove the partial authenticator.")
            return None
        
        print("\nAuthenticator successfully finalized!")
        
        refresh_token = None
        
        print("Getting refresh token...")
        test_code = getGuardCode(shared_secret)
        
        update_data = {
            'client_id': client_id,
            'steamid': steamid,
            'code': test_code,
            'code_type': '3'
        }
        
        update_response = session.post(
            'https://api.steampowered.com/IAuthenticationService/UpdateAuthSessionWithSteamGuardCode/v1/',
            data=update_data,
            timeout=30
        )
        
        if update_response.status_code != 200:
            print("Warning: Failed to update auth session")
        
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
            new_access_token = tokens.get('access_token')
            refresh_token = tokens.get('refresh_token')
            
            if new_access_token and refresh_token:
                access_token = new_access_token
                break
        
        if not refresh_token:
            print("Warning: Could not obtain refresh token")
            refresh_token = ""
        
        mafile_data = {
            'shared_secret': shared_secret,
            'serial_number': token_gid,
            'revocation_code': revocation_code,
            'uri': uri,
            'server_time': server_time,
            'account_name': account_name,
            'token_gid': token_gid,
            'identity_secret': identity_secret,
            'secret_1': secret_1,
            'status': 1,
            'device_id': generate_device_id(steamid),
            'fully_enrolled': True,
            'Session': {
                'SessionID': '',
                'SteamLogin': '',
                'SteamLoginSecure': '',
                'WebCookie': '',
                'OAuthToken': '',
                'SteamID': steamid,
                'AccessToken': access_token,
                'RefreshToken': refresh_token
            }
        }
        
        return mafile_data
        
    except Exception as e:
        print(f"Exception occurred: {e}")
        return None

def save_mafile(steamid, mafile_data):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    mafiles_dir = os.path.join(script_dir, 'maFiles')
    
    if not os.path.exists(mafiles_dir):
        try:
            os.makedirs(mafiles_dir, mode=0o700)
        except Exception as e:
            print(f"Failed to create maFiles directory: {e}")
            return None
    
    filename = f"{steamid}.maFile"
    filepath = os.path.join(mafiles_dir, filename)
    
    if os.path.exists(filepath):
        backup_path = filepath + '.backup'
        try:
            if os.path.exists(backup_path):
                os.remove(backup_path)
            os.rename(filepath, backup_path)
            print(f"Existing file backed up to: {backup_path}")
        except Exception as e:
            print(f"Warning: Could not backup existing file: {e}")
    
    try:
        with open(filepath, 'w') as f:
            json.dump(mafile_data, f, indent=2)
        
        try:
            os.chmod(filepath, 0o600)
        except:
            pass
        
        return filepath
    except Exception as e:
        print(f"Failed to save file: {e}")
        return None

def main():
    print("="*60)
    print("STEAM AUTHENTICATOR - ADD NEW ACCOUNT")
    print("="*60)
    print("\nThis will add Steam Guard Mobile Authenticator to your account.")
    print("\nREQUIREMENTS:")
    print("  - Your Steam username and password")
    print("  - Access to your phone for SMS verification")
    print("  - Account must NOT already have Mobile Authenticator")
    print("\nWARNING:")
    print("  - You will receive a REVOCATION CODE")
    print("  - Write it down immediately!")
    print("  - Without it, you may lose access to your account")
    print("="*60)
    
    username = input("\nEnter Steam username: ").strip()
    if not username or username.lower() == 'cancel':
        print("Setup cancelled.")
        return
    
    password = input("Enter Steam password: ").strip()
    if not password or password.lower() == 'cancel':
        print("Setup cancelled.")
        return
    
    print("\n" + "="*60)
    print("Starting authenticator setup...")
    print("="*60)
    
    mafile_data = add_authenticator(username, password)
    
    if mafile_data:
        steamid = mafile_data['Session']['SteamID']
        
        print("\nSaving authenticator data...")
        filepath = save_mafile(steamid, mafile_data)
        
        if filepath:
            print(f"\n{'='*60}")
            print("SUCCESS! AUTHENTICATOR LINKED!")
            print(f"{'='*60}")
            print(f"Account: {mafile_data['account_name']}")
            print(f"SteamID: {steamid}")
            print(f"File saved: {filepath}")
            print(f"\n{'='*60}")
            print("REVOCATION CODE (SAVE THIS!):")
            print(f"{mafile_data['revocation_code']}")
            print(f"{'='*60}")
            print("\nThis code can remove your authenticator if you lose access.")
            print("Store it in a safe place separate from this computer!")
            print(f"{'='*60}\n")
            
            print("Testing code generation...")
            test_code = getGuardCode(mafile_data['shared_secret'])
            print(f"Current Steam Guard Code: {test_code}")
            print("\nYou can now use this code to login to Steam.")
            print("The code changes every 30 seconds.")
            print(f"\n{'='*60}")
            print("Setup complete! You can now run SteamGuard.py")
            print(f"{'='*60}\n")
        else:
            print("\nERROR: Failed to save .maFile")
            print(f"Your revocation code is: {mafile_data['revocation_code']}")
            print("Please save this code before closing!")
    else:
        print("\n" + "="*60)
        print("Failed to add authenticator")
        print("="*60)
        print("\nPossible reasons:")
        print("  - Account already has an authenticator")
        print("  - Incorrect username or password")
        print("  - Network connection issues")
        print("  - Steam servers are down")
        print("\nPlease check and try again.")
        print("="*60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nCancelled by user")
    except Exception as e:
        print(f"\nUnexpected error: {e}")

