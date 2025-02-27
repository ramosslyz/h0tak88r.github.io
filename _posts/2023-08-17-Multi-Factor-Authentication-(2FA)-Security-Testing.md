---
title: Multi Factor Authentication (2FA) Security Testing
author: h0tak88r
date: 2023-08-17
categories: [Methodology]
tags: [2FA,Web Penetration Testing]
pin: false
---
# Introduction
**In the name of Allah, most gracious and most merciful**

Greetings, fellow security enthusiasts!

Imagine a lock that requires not just one, but two secret keys to open. That's Multi-Factor Authentication (2FA) in a nutshell – an extra layer of defense that's become a game-changer in keeping digital front doors locked against cyber intruders.

In this guide, we're diving into the world of 2FA security. Think of it as a treasure map that leads us through uncharted territory, where we'll uncover hidden vulnerabilities, test their strength, and equip ourselves with tools to ensure that 2FA is as solid as a fortress.

Whether you're a seasoned pentester or just starting out on your bug-hunting adventure, join us as we unravel the secrets of Multi-Factor Authentication, one factor at a time!
# 1. 2FA Setup

## 2FA Secret Cannot be Rotated [P4]

The 2FA secret is a cryptographic key that is shared between the user and the application. It is used to generate time-based one-time passwords (TOTPs) for authentication. Rotating the secret means changing this key periodically to enhance security. If the 2FA secret cannot be rotated, it means that once the secret is compromised, an attacker could potentially gain ongoing access to the account without the user's knowledge, as there is no way for the user to change the secret.

### Steps

```python
1. Login to the application 
2. Setup two factor authentication
3. After the 2FA secret is created, observe that there is no way in which the secret can be rotated
```

> This is a security weakness because if an attacker gains access to the 2FA secret, they could potentially use it to generate valid authentication codes and bypass the 2FA protection.
> 

References

- https://bugcrowd.com/disclosures/0c8a87aa-f10f-4174-b6d8-56c365062910/2fa-secret-is-not-rotated
- https://zofixer.com/what-is-weak-2fa-implementation-2fa-secret-cannot-be-rotated-vulnerability/

## 2FA Secret Remains Obtainable After 2FA is Enabled [P4]

The scenario "2FA Secret Remains Obtainable After 2FA is Enabled" in the Bugcrowd VRT refers to a vulnerability where, even after setting up two-factor authentication (2FA) for an account, the 2FA secret or key remains accessible to unauthorized individuals. This is a serious security flaw because the 2FA secret is a critical component of the authentication process, and if it is obtainable by attackers, it significantly weakens the overall security of the account.

### Steps

```python
If Target allows using 2FA authenticator like google authenticator or Microsoft authenticator etc... 

Try to Find a path that leaks QR code Or the secret that shows when enable the 2fa authentication

Analyze JS Files and try to understand how the target generate the secret 

test if the 2FA secret is still retrievable even after the 2FA feature has been activated by Replay Attacks or something
```

### References

- https://bugcrowd.com/vulnerability-rating-taxonomy
- https://github.com/bugcrowd/vulnerability-rating-taxonomy/issues/203

# 2FA Setup Logic Flaw [Varient]

The "Flawed Authenticator Attachment in Web Application 2FA Setup" vulnerability exposes a critical flaw in the process of attaching an authenticator app for two-factor authentication (2FA) within a web application. This vulnerability allows an attacker to manipulate the verification step of attaching the authenticator, compromising the intended security benefits of the 2FA mechanism and leading to potential account compromise/damadge as there is no real authenticator attached to the account.

### Steps

```python

1. Login and Initiate 2FA Setup: Log in to the web application using valid credentials. Navigate to the section for setting up 2FA in your account settings.
2. Start Authenticator Attachment: Begin the process of attaching an authenticator app for 2FA.
3. Provide Incorrect 2FA Code and Capture the Request: Enter an incorrect 2FA code from the authenticator app. Capture the request made by the application.
4. Intercept the Response and Manipulate it to a Successful Response: Intercept the response sent by the application and modify it to indicate a successful verification, even though the provided 2FA code was incorrect.
Impact: User can't login anymore
```

## Old session does not expire after setup 2FA [P4]

Old sessions persist after enabling 2FA, letting attackers access accounts even with 2FA. This undermines security and could lead to unauthorized actions. Developers must invalidate old sessions upon 2FA activation for robust protection.

### Steps

```python
1. Login to the application in two different browsers and enable 2FA from 1st session.
2. Use 2nd session and if it is not expired, it could be an issue if there is an insufficient session expiration issue.
3. In this scenario if an attacker hijacks an active session before 2FA, it is possible to carry out all functions without a need for 2FA
```

### References

- https://bugcrowd.com/disclosures/4147cfbb-a808-4504-9b4f-2a8b68e17d62/old-session-does-not-expire-after-setup-2fa

## Enable 2FA without verifying the email [ P3 ]

### Steps

```python
1. The attacker signs up with victim's email (Email verification will be sent to victim's email). 
2. Attacker is able to log in without verifying the email. 
3. Attacker adds 2FA. 
4. the victim can't register an account with victim email. If the victim reset the password, the password will change, but the victim can't login because 2FA.
```

### References

- https://hackerone.com/reports/649533

## IDOR Leads To ATO [ P2, P3 ]

### Steps

```python
1. As a user1, register, skip 2FA, copy the ID.
2. Register an account user2, register, perform a 2FA request but with ID from user1.
3. 2FA is enabled now on the account user1!
4. Perform a request /api/2fa/verify with valid code and ID of user1.
```

### References

- https://hackerone.com/reports/810880

# 2. 2FA Bypass

## 2FA Code is Not Updated After New Code is Requested [ P5 ]

Using sms, requesting multiple 2FA codes (without using them) results in the same code being sent

### Steps

```python
1. Try Login to your account 
2. In 2FA Request resend the code 
3. If the old and new code is the same then there is an issue 
Impact: code that is not updated after a request new one makes it easier for a hacker to brute force or guess the code
```

### Resources

- https://github.com/bugcrowd/vulnerability-rating-taxonomy/issues/289

## Old 2FA Code is Not Invalidated After New Code is Generated [ P5, P4 ]

- A new 2FA code is generated for the user.
- The old 2FA code from a previous generation is not immediately marked as invalid or revoked.
- An attacker could potentially use the old 2FA code, even though a new one has been generated.

### Steps

```python
1. Try Login to your account 
2. in 2fa page request a new code 
3. Enter the Old code 
---------
1. Request a 2FA code and use it 
2. Now, Re-use the 2FA code and if it is used successfully that's an issue.
3. Also, try to re-use the previously used code after long time duration say 1 day or more. That will be an potential issue as 1 day is enough duration to crack and guess a 6-digit 2FA code.
-------------------
1. authenticator generate code every 30 sec
2. wait 30 sec then use the code 
-----------------------------------------------------------------
1. Remove authenticator from your account and generate New 2FA secret and attach it with authenticator 
2. Use codes generated by old 2fa secret with authenticator
```

### References

- https://github.com/bugcrowd/vulnerability-rating-taxonomy/issues/289
- https://hackerone.com/reports/695041
- https://gitlab.com/gitlab-org/gitlab/-/issues/121666

## 2FA Code Leakage in Response [ P3 ]

### Steps

```python
1. At 2FA Code Triggering Request, such as Send OTP functionality, capture the Request.
2. See the Response to this request and analyze if the 2FA Code is leaked in the response somewhere.
```

### References

- https://hackerone.com/reports/1276373

## Lack of Brute-Force Protection [ P4 ]

This involves all sort of issues which comes under security misconfiguration such as lack of rate limit, no brute-force protection, etc.

### Steps

```python
1. Request 2FA code and capture this request.
2. Repeat this request for 100-200 times and if there is no limitation set, that's a rate limit issue.
3. At 2FA Code Verification page, try to brute-force for valid 2FA and see if there is any success.
4. You can also try to initiate, requesting OTPs at one side and brute-forcing at another side. Somewhere the OTP will match in middle and may give you a quick result
5. try bypass rate limit protection by changing the subdomain in host header
-----------
1. go to the 2FA page
2. Click on the "Resend code" Button
3. Capture this request 
4. Resend it 50 times
Impact: You won't be able to bypass the 2FA but you will be able to waste the company's money.
----------
# no rate limit after reset password 
1. A user sends a password reset message to user's registered email.
2. Go to "Password Reset" page from #1's message.
3. Set a new password and Brute force two-factor auth code
```

### References

- https://hackerone.com/reports/1060518
- https://hackerone.com/reports/121696

## Missing 2FA Code Integrity Validation [ P3 ]

### Steps

```python
1. Request a 2FA code from Attacker Account.
2. Use this valid 2FA code in the victim 2FA Request and see if it bypasses the 2FA Protection. 
1. Check if you can get the token from your account and try to use it to bypass the 2FA in a different account.
```

## Bypass 2FA with null or 000000 or Blanc  [ P3 ]

### Steps

```python
1. log in to your account
2. Enable 2FA
3. Logout
4. Login again and notice OTP is asked
5. Now using the Burp suite intercept the POST request by   sending the incorrect code. [Do not forward]
6. Before forwarding the request to the server, remove the code and forward | OR Enter the code 000000 or null to bypass 2FA protection.
7. Turnoff Intercept and notice that your login request has been fulfilled
```

### References

- https://hackerone.com/reports/897385
- https://hackerone.com/reports/897385

## 2FA Referrer Check Bypass | Direct Request [ P2, P3 ]

### Steps

```python
1. Directly Navigate to the page which comes after 2FA or any other authenticated page of the application. 
2. See if this bypasses the 2FA restrictions. 
3. try to change the Referrer header as if you came from the 2FA page.
```

## Misconfiguration of Session permissions [ P4, P3 ]

### Steps

```python
1. Using the same session start the flow using your account and the victim's account.
2. When reaching the 2FA point on both accounts.
3. complete the 2FA with your account but do not access the next part.
4. Instead of that, try to access the next step with the victim's account flow.
5. If the back-end only set a Boolean inside your sessions saying that you have successfully passed the 2FA you will be able to bypass the 2FA of the victim.
```

## Lack of rate limit in the user's account when logged in [ P4 ]

### Steps

```python
Sometimes you can configure the 2FA for some actions inside your account (change mail, password...). 

However, even in cases where there is a rate limit when you tried to log in, there isn't any rate limit to protect actions inside the account.
```

### Changing the 2FA mode Leads to Bypass the code [ P3 ]

### Steps

```python
1. Use burp suite or another tool to intercept the requests 
2. Turn on and configure your MFA
3. Login with your email and password 
4. The page of MFA is going to appear
5. Enter any random number 
6. when you press the button "sign in securely" intercept the request POST auth.target.com/v3/api/login and in the POST message change the fields: "mode":"sms" by "mode":"email" "secureLogin":true by "secureLogin":false
send the modification and check, you are in your account! It was not necessary to enter the phone code. 

```

### References

- https://hackerone.com/reports/665722

## Bypass Using OAUTH [ P5 ]

### Steps

```python
Site.com requests Facebook for OAuth token > Facebook verifies user account > Facebook sends callback code > Site.com logs a user in without requesting 2fa code
```

### References

- https://hackerone.com/reports/178293

## Random timeout issue on a Two-Step Verification endpoint [ P3 ]

### Steps

```python
enter 2 wrong attempts in a short time  
this may leads to bypass the 2FA process
```

### References

https://hackerone.com/reports/1747978

# 3. Disable 2FA

## Lack of Brute-Force Protection Disable 2FA [ P4 ]

### Steps

```python
(1) Login in your target
(2) Click on your username 
(3) Navigate to Two-factor authentication --> Disable 2FA 
(4) add random password in Please confirm your identity to register a new Two-Factor Authenticator 
(5) Capture the request and send it to Intruder for fuzz 
```

### References

- https://hackerone.com/reports/1465277

## Disable 2FA via CSRF (Leads to 2FA Bypass) [ P4 ]

### Steps

```python
1. Go to https://pandao.ru/profile/settings and sign up for two accounts. In which first is attacker's account and second is Victim’s 
2. Log in to the Attackers account and capture the Disable 2FA request in the Burp suite and generate CSRF POC.
3. Save the CSRF POC file with extension .html 
4. Now log in to Victim’s account in Private Browser and fire that CSRF file. Now you can see that It disables 2FA which leads to 2FA Bypass 
-------------------
1. Capture request in burpsuite
2. Engagement tools> Generate CSRF POC 
3. Pass null chars in token value so function will over-ride
4. Submit twice for overriding
5. 2FA disabled

Just add this for extra
<!-- Reload page every 5 seconds. -->
 <body onload="timer = setTimeout('auto_reload()',5000);">
</body>
</html>
```

### References

- https://vbharad.medium.com/2-fa-bypass-via-csrf-attack-8f2f6a6e3871
- https://hackerone.com/reports/670329
- https://twitter.com/adityashende17/status/1241093166540849152

## Password Reset/Email Check → Disable 2FA [ P5,P4 ]

### Steps

```python
* Create an Account and Turn On 2FA. 
* Logout from that account. 
* Now, Go to Forget Password-Reset page. 
* Change your password. 
* Now try to log in, If you are not asked to enter a 2FA code, You can report.
```

### References

- https://infosecwriteups.com/how-i-bypass-2fa-while-resetting-password-3f73bf665728

## Logic Bug Disable 2FA [ P3 ]

### Steps

```python
1. Open Your BurpSuite and Turn on the intercept 
2. Go To 2Factor Authentication page click the red buttons "Disable two factor ...." 
3. Put any wrong password and copy all the header 
4. Go to repeater and make a POST request to https://localizestaging.com/api/user/two-factor/set also Paste the header here.
5. add a body request like this method=sms&phone=%2B62-hacker-phone-number then click GO 
6. Bypassed !
```

### References

- https://hackerone.com/reports/783258

## Backup Code Abuse [ Varient ]

### Steps

```python
Apply same techniques used on 2FA such as Response/Status Code Manipulation, Brute-force, etc. to bypass Backup Codes and disable/reset 2FA

Backup codes are generated immediately after 2FA is enabled and are available on a single request. After each subsequent call to the request, the codes can be regenerated or remain unchanged (static codes). 

If there are CORS misconfigurations/XSS vulnerabilities and other bugs that allow you to “pull” backup codes from the response request of the backup code endpoint, then the attacker could steal the codes and bypass 2FA if the username and password are known.
```

### References

- https://hackerone.com/reports/113953
- https://hackerone.com/reports/100509

## Password not checked when 2FA Disable [ P5, P4 ]

### Steps

```python
1. Check when u try to disable 2FA there is no identity confirmation methods like 2fa code otr password 
-------------------------------------

1. go to your account and activate the 2FA from /settings/auth
2. after activating this option click on the Disable icon beside Two-factor authentication.
3. a new window will open asking for Authentication or backup code - Password to confirm the disabled
4. in the first box enter a valid Authentication or backup code and in the password filed enter any random/wrong password and click save.
5. the option will be disabled successful without check the validation of the password.
```

### Resources

- https://hackerone.com/reports/587910

## Clickjacking on 2FA Disabling Page [ P4 ]

### Steps

```python
1. Try to Iframe the page where the application allows a user to disable 2FA 
2. If Iframe is successful, try to perform a social engineering attack to manipulate victim to fall in your trap.
```
# 2FA Security Testing Mind-Map
- https://github.com/h0tak88r/Mind_Maps/blob/main/2FA%20Security%20Testing.xmind
## The End

With this, we conclude our exploration of 2FA security. Remember, the path of cybersecurity is never-ending. Until we meet again on our next endeavor, stay committed to safeguarding the digital realm. Farewell for now!
