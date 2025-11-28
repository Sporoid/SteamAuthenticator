# STPY - Steam Guard Authenticator

A Python-based Steam Guard authenticator that generates time-based one-time passwords (TOTP) and manages Steam mobile confirmations directly from your terminal.

## Features

### 🔐 TOTP Code Generation
- Generates 5-character Steam Guard codes
- Syncs with Steam's time server for accuracy
- Supports multiple Steam accounts simultaneously
- Auto-refreshes every 30 seconds

### ✅ Mobile Confirmations
- View pending trade confirmations
- Approve individual confirmations
- Batch approve all confirmations
- Multi-account confirmation management

### 🎨 User Interface
- Clean terminal-based interface
- Animated progress bar synced to 30-second TOTP cycle
- Real-time status updates
- Cross-platform support (macOS, Linux, Windows)

## Installation

### Prerequisites
- Python 3.x
- Required libraries: `requests`, `rsa`

### Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Or install manually
pip install requests rsa

# Run the application
python SteamGuard.py
```

## Usage

### Normal Mode (TOTP Codes)
The application displays a live dashboard with individual progress bars for each account:

```
============================================================
STEAM GUARD AUTHENTICATOR
============================================================

Press 'Ctrl+C' to stop | Press '2' to enter verification mode

  trikce          | Code: B2C4D | [████████░░░░░░░] 18s
  juanpi1588      | Code: HV3GR | [████████░░░░░░░] 18s
  xkce27          | Code: G97QR | [████████░░░░░░░] 18s

────────────────────────────────────────────────────────────
[████████████████████████──────────────────────────────────]
────────────────────────────────────────────────────────────
```

**Features:**
- ⚡ **Real-time Updates** - Updates every second with current codes and progress
- 🔄 **Synchronized Accounts** - All accounts share the same Steam server time
- 🎯 **30-Second Cycles** - Progress bars match TOTP 30-second intervals  
- 📊 **Visual Progress** - Bar shows exact time remaining until next code
- 🔒 **Steam Time Sync** - Syncs with Steam's official time server on startup

### Verification Mode (Confirmations)
Press `2` during the progress bar to enter verification mode:

```
============================================================
PENDING CONFIRMATIONS: 3
============================================================

1. [account1] Confirm Trade Offer
   Creator ID: 76561198012345678
   Verification Code: [45678]
   Trade with User123 - 5 items

2. [account2] Market Listing
   Creator ID: 76561198087654321
   Verification Code: [54321]
   Sell Item XYZ for $10.50

3. [account3] Account Recovery
   Creator ID: 5329691627136527629
   Verification Code: [27629]
   Verify account recovery request

============================================================
SELECT ACTION:
============================================================
[Number] - Select confirmation
[A]      - Approve All
[D]      - Deny All
[Q]      - Quit
============================================================

Your choice: 1

============================================================
SELECTED: [account1] Confirm Trade Offer
============================================================

ACTION:
[1] - APPROVE
[2] - DENY
[Q] - Cancel
============================================================

Your choice: 1

Approving...
✓ Successfully approved!

Press Enter to return...
```

**Two-Step Process:**

1. **Select** the confirmation number, or choose Approve/Deny All
2. **Confirm** your action (with warning for batch operations)

**Safety Features:**
- Warning prompts before approving/denying all
- Per-confirmation verification code in brackets [XXXXX]
- Verification codes match Steam's confirmation page exactly (last 5 digits of Creator ID)
- Two-step action confirmation prevents accidents
- Detailed information to make informed decisions

**Confirmation Types:**
- **Trade** - Trading items with another user
- **Market Listing** - Selling items on Community Market
- **Account Recovery** - Account security verification
- **Phone Number Change** - Changing account phone number
- **Feature Opt-Out** - Opting out of features

*Types are from Steam's official API (EMobileConfirmationType enum)*

## File Structure

```
STPY/
├── SteamGuard.py              # Main application
├── refresh_all_accounts.py    # Token refresh utility
├── requirements.txt           # Python dependencies
├── maFiles/                   # Steam authenticator files (NOT included in git)
│   └── *.maFile              # Account authentication data
├── README.md                 # This file
└── .gitignore                # Git ignore rules
```

## Utility Scripts

### refresh_all_accounts.py
Manually refresh all expired tokens for all accounts:
```bash
python refresh_all_accounts.py
```

This script:
- Checks all accounts for expired tokens
- Automatically logs in with stored credentials
- Submits 2FA codes automatically
- Updates all .maFile files with fresh tokens
- Shows summary of successes/failures

## Configuration

### maFile Format
Each account requires a `.maFile` JSON file in the `maFiles/` directory containing:
- `shared_secret` - For TOTP generation
- `identity_secret` - For confirmations
- `account_name` - Steam username
- `Session` data with SteamID and AccessToken

## How It Works

### TOTP Generation
1. Queries Steam's time server for accurate timestamp
2. Generates HMAC-SHA1 hash using shared_secret
3. Converts to Steam's custom base-26 character set
4. Displays 5-character code that refreshes every 30 seconds

### Confirmation System
1. Generates confirmation key using identity_secret
2. Fetches pending confirmations from Steam API
3. Authenticates using JWT access tokens (auto-refreshes if expired)
4. Sends approval/denial requests to Steam servers

### Automatic Token Refresh
1. Detects expired access tokens
2. Gets RSA public key from Steam
3. Encrypts password using RSA
4. Begins authentication session
5. Automatically submits 2FA code from shared_secret
6. Polls for new tokens
7. Updates .maFile with fresh tokens
8. All happens seamlessly in the background

## Security Notes

⚠️ **Important Security Considerations:**

- `.maFile` files contain sensitive authentication data
- Keep your `maFiles/` directory private (chmod 700)
- Access tokens grant full account access
- Never share or commit `.maFile` files to version control
- Store revocation codes separately

The `.gitignore` file is configured to prevent accidental commits of sensitive data.

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `2` | Enter verification mode |
| `Ctrl+C` | Exit application |
| `Enter` | Return from verification mode |

## Technical Details

- **Language:** Python 3.x
- **Authentication:** HMAC-SHA1 TOTP
- **Time Sync:** Steam API (`ITwoFactorService/QueryTime`)
- **Confirmations:** Steam Community Mobile API
- **Progress Bar:** 30-second cycle matching TOTP interval

## Troubleshooting

**Codes not working?**
- Ensure system time is accurate
- Check Steam API connectivity
- Verify shared_secret in .maFile is correct

**Confirmations not loading?**
- Verify AccessToken is not expired
- Check identity_secret is valid
- Ensure network access to steamcommunity.com

**Input not working?**
- macOS/Linux: Non-blocking input uses `select` module
- Windows: Input checking may have limited support

## Platform Support

- ✅ macOS (tested)
- ✅ Linux (should work)
- ⚠️ Windows (limited input support)

## Updates

**Latest Changes (November 27-28, 2025):**
- ✅ Fixed progress bar timing to match 30-second TOTP cycle
- ✅ Added Steam mobile confirmation support
- ✅ Implemented multi-account confirmation management
- ✅ Added batch approval functionality
- ✅ Fixed confirmation API based on SteamDesktopAuthenticator analysis
  - Corrected endpoint from /getconf to /getlist
  - Switched from Bearer token to cookie-based authentication
  - Updated User-Agent to okhttp/3.12.12
  - Added proper sessionid and mobile client cookies
- ✅ **Automatic Token Refresh** - Implements full Steam authentication flow
  - RSA password encryption
  - Automatic 2FA code submission
  - Token refresh without SteamDesktopAuthenticator
  - Works seamlessly when tokens expire

## License

This is a personal utility tool. Use at your own risk.

## Disclaimer

This tool interacts with Steam's authentication systems. Ensure you understand the security implications before use. Always keep your authentication files secure and private.

