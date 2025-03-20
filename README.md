
# 🔥 Cognito Brute Forcer - README

## 📖 Overview
This tool is designed for **penetration testers**, **red teamers**, and **bug bounty hunters** targeting AWS Cognito applications. It allows you to brute force username/password combinations against a Cognito User Pool.

The script supports:
✅ Multi-threaded operation \
✅ Region discovery and locking \
✅ AWS Cognito rate-limit detection (no redundant prints) \
✅ Success and "unconfirmed" handling \
✅ JSON output \
✅ Hacker color-coded console output

---

## ⚙ How AWS Cognito Works (Authentication Flow)
AWS Cognito uses an **App Client ID** and sometimes a **Client Secret** to authenticate against a **User Pool**. Some public-facing apps do not use a Client Secret (mobile/SPA clients), but some do.

- **Client ID** is required.
- **Client Secret** may be required if the Cognito app is configured with it.

Your goal is to find these two values.

---

## 🔍 How to Extract the `client_id` and `client_secret`

### ✅ **Step 1: Scan JavaScript files**
Use tools like `katana`, `gau`, or `hakrawler` to extract JS links from target applications:
```
katana -u https://target.app -jc
```

### ✅ **Step 2: Grep through JS files**
Look for patterns like:
```javascript
"client_id": "xxxxxxxxxxxxxx"
"ClientId": "xxxxxxxxxxxxxx"
"clientSecret": "xxxxxxxx"
"UserPoolId": "us-east-1_ABC123"
etc.
```

Regex pattern example:
```
grep -E 'client_id|ClientId|clientSecret|UserPoolId' *.js
```

### ✅ **Step 3: Identify Cognito Client Usage**
You might see AWS Amplify or Cognito-specific configs like:
```javascript
const config = {
    region: 'us-east-1',
    userPoolId: 'us-east-1_ABC123',
    clientId: '4abcd1234567890xyz',
    clientSecret: 'abcdsecretvalue'
}
```

This `clientId` and `clientSecret` is exactly what you need for this tool.

---

## 🛠 Usage Example

### ✅ **Combo Mode (user:pass or user,pass)**
```
python3 cognito_brute_final_safe.py <client_id> <client_secret> -c combos.txt --json -t 30
```

### ✅ **Separate User and Password Lists**
```
python3 cognito_brute_final_safe.py <client_id> <client_secret> -u users.txt -p passwords.txt --json
```

### ✅ **Output Example (Color-coded terminal):**
```
[❌ INVALID] us-east-1 => user1:wrongpass -> Invalid credentials
[🔎 UNCONFIRMED] us-east-1 => admin:CorrectPassword -> User not confirmed
[🐸 SUCCESS] us-east-1 => admin:CorrectPassword
[🚨 RATE LIMITED] us-east-1 => user2 -> Password attempts exceeded. Skipping user...
```

### ✅ **JSON Output (`results.json`) Example:**
```json
[
  {
    "region": "us-east-1",
    "username": "admin",
    "password": "password123",
    "status": "unconfirmed"
  },
  {
    "region": "us-east-1",
    "username": "admin",
    "password": "AdminPassword",
    "status": "success",
    "response": "{AWS Cognito Response}"
  }
]
```

---

## 🚀 Features
✅ Multi-threaded for high speed \
✅ **Region locking** (stops testing other regions once correct one found) \
✅ **Rate-limiting detection** (stops retesting locked users) \
✅ Stops brute-forcing after first valid/unconfirmed hit per user \
✅ JSON output (`results.json`) \
✅ Combo or user/pass mode

---

## ❌ Rate Limiting Behavior
✅ The tool prints "[🚨 RATE LIMITED]" **once per user** \
✅ Immediately stops testing that user \
✅ Continues testing remaining users 

Example:
```
[🚨 RATE LIMITED] us-east-1 => admin -> Password attempts exceeded. Skipping user...
```

---

## ⚠ AWS Cognito Edge Cases
- **UserNotConfirmedException**: Valid credentials but user never confirmed email/phone. \
- **NotAuthorizedException**: Bad password or locked account. \
- **Rate Limit**: AWS Cognito stops processing after multiple bad attempts. Handled cleanly.

---

## 📌 Real World Usage Tip
- Run this on targets using **AWS Amplify, Cognito Auth** \
- Look for JS references to `AmazonCognitoIdentity`, `AWS.config.credentials`, or `new CognitoUser()` \
- Works great during bug bounty token extraction tests

---

## 💣 Future Enhancements (if needed)
✅ Retry logic \
✅ Export `rate_limited_users` list \
✅ Multiprocessing mode \
✅ Auto-confirm unconfirmed users (if possible) 

---

## ✅ Credits
Created for **Offensive Security / Red Team Use** by Specters.

---

Run at your own risk. AWS Cognito is sensitive to rate limits. And you will burn valid accounts if not careful...

---
