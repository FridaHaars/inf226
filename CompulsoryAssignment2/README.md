# “HeadBook” Example Project (INF226, 2023)

* Flask docs: https://flask.palletsprojects.com/en/3.0.x/
* Flask login docs: https://flask-login.readthedocs.io/en/latest/
* Using "Log in with *social network*": https://python-social-auth.readthedocs.io/en/latest/configuration/flask.html

## To Use

### Set up virtual environment and install dependencies

Use the [`venv`](https://docs.python.org/3/library/venv.html) command to create a virtual environment. Windows::

```sh
python -m venv .venv  # or possibly python3 or py
.venv/Scripts/activate
pip install -r requirements.txt
```

You can exit the virtual environment with the command `deactivate`.

### Run it

```sh
flask -A headbook:app run --reload
```

### Additional Libraries

`colour` is required for `validate_info.py` in order to check user input on profile. 

```sh
pip install colour 
```




# 2A

### Performing SQL Injection Attack
Goal: *Delete users in user database through SQL injection!* 


1. **Loading the site**

Running the program gives the following output in terminal as users are added to database `users.db`

![alt text](https://github.com/FridaHaars/inf226/tree/main/CompulsoryAssignment2/static/screenshots/1.png "Terminal output upon first run")
 
I thus have the login credentials etc. to two users alice and bob (they are also blatantly exposed in source code). Inspecting the site in the browser debugger I can also see the two usernames in debugging `script.js`, and bruteforcing their passwords might not be much of a challenge due to their simplicity.

 
2. **Finding SQL query**

* When I enter nothing into the login fields and look at what happens in the terminal, the following SQL query is revealed:

```sh
SELECT id, username, password, info FROM users WHERE username = '';
```

This is a format I can use in order to manipulate the program. 
 
 
3. **Testing...**

When I insert only a single quote into the Username: field, I get an Internal Server Error. This would indicate that the input is not sanitized or filtered. 

 
4. **Exploit**

I input the following into the `Username:` field:

```sh
'; DELETE FROM users; SELECT id, username, password, info FROM users 
WHERE username = '
```

or simply

```sh
'; DELETE FROM users;--
```


`--` is a comment indicator in SQL, meaning that the rest of the input is ignored.
In order to check whether it worked, I first successfully login as alice. After inserting the above command, the previously valid login credentials for user alice no longer work, and when I input them return to login page. Hence, the user database has been wiped. I could also inspect contents ofthe database through VSCode by opening the database with help from SQLite3 extension.

 
5. **Cleanup**

Afterwards I delete the database `users.db`, so that it can be set up again the next time the program is run.

*Sources*
https://www.invicti.com/blog/web-security/fragmented-sql-injection-attacks/ 
https://www.youtube.com/watch?v=ciNHn38EyRc
https://portswigger.net/web-security/sql-injection 
https://en.wikipedia.org/wiki/String_interpolation#:~:text=cached%20for%20reuse.-,Security%20issues,-%5Bedit%5D



## SQL Injection Attack Prevention

* I implemented prepared statements for all queries:

*Example: Changed the body of `add_token()` from*

```sh
[...]
sql_execute(
    f"INSERT INTO tokens (user_id, token, name) VALUES ({self.id}, '{token}', '{name}');"
)
```

*to*
```sh 
[...]
data = (self.id, token, name)
sql = "INSERT INTO tokens (user_id, token, name) VALUES (?, ?, ?);"
sql_execute(sql, data)
```        


Now, if I attempt to insert `'; DELETE FROM users;--`, the user table is not wiped! Yay. Also:
* If I insert a single quote ‘ I do not get an error.
* In both cases I get the flash message `User does not exist.`



*ALSO...*
- *See first paragraph of 2B notes*


*Sources*
https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
https://www.psycopg.org/docs/usage.html#the-problem-with-the-query-parameters




# 2B 

In order to perform an XSS-attack in the way suggested by the task text, I had to have a fake user. So I reverted all changes from 2a, performed the following SQL injection to add a fake user: 

```sh
'; INSERT INTO users (id, username, password, info) VALUES (3, "frida", "mohaha",'{"color":"blue"}');--
```
```sh
'; INSERT INTO tokens (user_id, token, name) VALUES (3, '{secrets.token_urlsafe(32)}', 'frida');--
```

I also added birthdate/profile picture manually.

...and then implemented the SQL injection prevention measures again. 


![alt text](https://github.com/FridaHaars/inf226/blob/main/CompulsoryAssignment2/static/screenshots/2.png "HeadBook profiles")



**Now I am ready to perform the attack.**



## XSS Attack


I changed the About-section in my profile to read the following:

```sh
<img src="" onerror=alert('hacked!')>
```

Now, when a user clicks on my profile, an alert pops up:

![alt text](https://github.com/FridaHaars/inf226/blob/main/CompulsoryAssignment2/static/screenshots/3.png "Alert")

Thus I have altered the application by injecting my own executable code in a form that is executed in the browser. 

*Sources*
https://www.invicti.com/learn/cross-site-scripting-xss/#:~:text=in%20separate%20chapters.-,XSS%20attack%20vectors,-Common%20JavaScript%20language



### Solving Injection Problems with a Restrictive Content Security Policy


CSPs are HTTP reponse headers that can control which domains content can be loaded from, and report any violation back to the server. This content can be specified as scripts, images, stylesheets, etc. A CSP can e.g. demand that all scripts are loaded from the same site, or that image content from another specific site is allowed. Thus, we can solve some of the injection problems using CSPs by restricting the origin of loaded content. 
However, it is extremely important to implement the CSP correctly, and take into account the possibility that some old browsers don’t support the use of them.

*TODO: Implement CSP...*

*Sources*
https://tecadmin.net/content-security-policy/
https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
[Håkon's slides on Cross-site Scripting]



### Code Injection from /users/me

When I visit http://127.0.0.1:5000/users/me, a page that looks like a simplified version of my profile is loaded:

![alt text](https://github.com/FridaHaars/inf226/blob/main/CompulsoryAssignment2/static/screenshots/4.png "Profile details on /users/me")

This page just conveys the contents saved in the logged in user's profile. The line `<img src="" onerror=alert('hacked!')>` holds no power because it is **not executed**, it is just represented as plain text. Thus the code injection no longer works.



### Fixing Code Injection Problems in script.js

I used `µhtml` templates in order to fix the code injection problems in script.js. I modified the functions `format_field()` and `format_profile()` by inserting `html` in front of all content that was to be rendered into `elt`, and replaced `elt.innerHtml = ""` with `render(elt, html)`. 

Now, the formerly malicious line `<img src="" onerror=alert('hacked!')>` from my `About:`-section is represented as harmless text, and is not executed when a user clicks on my profile:

![alt text](https://github.com/FridaHaars/inf226/blob/main/CompulsoryAssignment2/static/screenshots/5.png "Home page after implementing with µhtml")

*Sources*
https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML
https://github.com/WebReflection/uhtml/blob/main/DOCUMENTATION.md





## 2C

### Dealing with Passwords

Passwords are stores *unhashed* in the database `users.db`. `app.py` imports `generate_password_hash` and `check_password_hash` from the `werkzeug.security` library, but these functions are never actually employed on any password or other sensitive information. If I open the database using SQLite3 in VSCode, I can see the table under `users` as follows:

![alt text](https://github.com/FridaHaars/inf226/blob/main/CompulsoryAssignment2/static/screenshots/6.png "users table from users.db: plaintext pw")

The passwords are stored in plaintext in the `password` column. 
There are also no restrictions on password length or contents, so the user is free to have any weak or strong password, or even an empty one. 
**None of this is in line with the best security practices.**



### Implementing Hashing with a Salt

I've implemented password hashing with a salt using the suggested `werkzeug.security` library, utilizing the following functions:

`generate_password_hash()` _In `save()` within `User` class_
- Param: *password*=self.password, *method*='scrypt', *salt_length*=8
- It generates a hash from the given password, and saves the hash to database through `sql_execute`. 

`check_password_hash()`: _In the `login()` route function_
- Param: *pwhash*=user.password, *password*=password.
- This checks whether the inserted password is equivalent to the hash stored in the database. If so, and if the username is correct, the user is logged in. If the password does not agree with the hashed password belonging to the given user in database, the prompt **Incorrect password.** is displayed. If the user is not in database, the prompt **User does not exist.** is displayed.
- I've created a helper `pw_validator(user, password)` to deal with the situations above. It is located within the module `password_check.py`, and returns *True* if username and password match; *False* if username exists but password is incorrect; and *None* if there is no user in database matching the given username. 

After implementing the hashing, I get the following contents in the `users` table, where we can see that they are no longer visible in plaintext: 

![alt text](https://github.com/FridaHaars/inf226/blob/main/CompulsoryAssignment2/static/screenshots/7.png "users table from users.db: hashed pw")



### Password Check

In addition to `pw_validator()`, the `password_check.py` module contains the following functions:

`check_password()`
- Param: pw
- Heavily reliant on the suggested StackOverflow discussion: https://stackoverflow.com/questions/16709638/checking-the-strength-of-a-password-how-to-check-conditions#32542964
- The rules are as follows:
1. Length from 8-64 characters
2. Must include digit
3. Must include uppercase letter
4. Must include lowercase letter
5. Must include symbol
- This is used to check whether the password is considered secure, by checking whether the key `'password_ok'` in the returning dictionary is true. Otherwise, the next function is used to display to user what shortcomings their proposed password has:

`error_message()` 
- Param: pw
- Checks whether the above demands are unfulfilled and prints an output message explaining which (if any) shortcomings the attempted password has. Then redirects the user to that they may alter their password accordingly.


I modify `save()` to demand that if a user is to be added to database, the password must meet the given demands. I also change the passwords of alice and bob, so that they are valid and ever so slightly more secure:

1. alice = pasSword359=
2. bob = Bananas#34

I test the changes by attempting to give bob a password that is too short, which gives the appropriate error message. bob is not added to database, and the program proceeds.

Now there are two possible sql-executions in `save()`: 
- one that updates the profile details incl. password iff the proposed password adheres to password rules; and 
- another that does **not** update the password if the password field is left empty

I had to update `my_profile()` as well, in order to check whether the user actually attempted to change their password. 
- the error message (i.e. the message that informs what is wrong with the proposed password) now only executes iff something has been entered into the password fields in profile 
- if there is no error, the password is updated



### Implementing Simple Access Control

I’ve implemented a fairly primitive access control, in which users are only permitted to see the full information on users they are buddies with. 

I created a function `is_buddies()` (see `user.py`) which compares user ids in the `buddies` table within the database, and returns a boolean value based on that information. In `get_users()` I use this function in order to check the buddies of the `current_user`. If a user is their buddy, they are added to `result` which determines what information is rendered to the home page. If the are *not* buddies, only the user’s username is added to the home page. The other information remains empty. 

I also utilize `is_buddies()` in `get_user()` in order to make sure that users cannot access non-buddy information through `URL/users/<userid>`. If a user attempts to access the information on a non-buddy through the URL, they receive the prompt **You are not buds with this user!**. 




# 2D Things to Consider

### Session Cookie Options, `secrets`, `SECRET_KEY`, and CSP

I created a **`secrets` module**, in which I placed all `config` settings. This module is included in `.gitignore`, so configuration settings will not be pushed to git. I also implemented a *random value* for the **`SECRET_KEY`** through the `secrets.token_urlsafe(8)` function.

I've set session cookies to the following:

```sh
SESSION_COOKIE_NAME = 'headbook_session'
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_SECURE = False
```

I've set `SESSION_COOKIE_SAMESITE` to `Strict`, because as the app is now, it will likely not break any functionality due to cross-origin requests, but rather contribute to protect against XSS-attacks like CSRF. This value may be modified later upon further implementation. `SESSION_COOKIE_SECURE` is set to the default `False`, because as of now my app is served over HTTP and not HTTPS.

It could surely benefit from a Content-Security-Policy header, especially to reduce the attack surface of the application. I did not have time to set it this time around, but it will be a consideration for further implementation. For now the SECURE_COOKIE_SAMESITE is set to Strict which can control how cookies can be sent, but a proper CSP could control where content can be loaded from as well.


### Threat Model and Traceability

In terms of *who* might attack this app, the answer may be "anyone". A potential attacker may be able to access confidential information with relative ease. 
Some of the changes made have increased the security. The password checks that are implemented, as well as the storing of those passwords and the waiting periods between login attempts, makes it harder for an attacker to access them, meaning that confidentiality has been improved. The integrity is also strengthened, because it's harder for an attacker to e.g. impersonate another user or perform a SQL injection. In terms of availability, a weakness that has been reduced is an attackers ability to perform SQL injection and alter or delete the database, keeping users from their accounts. The database may still be compromised in other ways, and other attacks (such as DDoS/DoS) could severely compromise availability. This could be reduced through e.g. recaptcha for the user login requests.
In order to know whether the security is good enough, the best approach might be testing and logging on the application. Take note of security breaches and close them up at once. In this implementation, some logging is performed by flask upon requests, but these logs are not stored anywhere to be analyzed later on. "Perfect" security might be close to impossible, but there are a lot of measures to be done in order to protect the application, its users and its contents.

https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
https://cheatsheetseries.owasp.org/cheatsheets/Web_Service_Security_Cheat_Sheet.html


### Additional Changes

* Installed extension Better Jinja and changed html -> html.j2 (as per Anya's suggestion on Discord).
* More **password** stuff: I made modifications to `login.html.j2` and the `login()` route. I've changed it so that if a user enters the wrong password three times, they receive a 30 seconds time penalty before they're allowed to try again. A variable `attempts` keeps track of how many times the user has entered the incorrect password. I had to change the login template in order to implement this. If `too_many_attempts` is set to True, the JS code executes, and the user is shown a prompt **You've entered the wrong password too many times. Please wait 30 seconds and try again (page will automatically reload when time penalty is over).**. If they attempt to login before the 30 second waiting period is over, they are reminded that the page will reload when it's over, and they're blocked from attempting again until that time. 
* I've started to separate the massive `app.py` somewhat, into several smaller modules: `user.py`, `user_info.py`, and `utils.py`, etc. This still needs some work.
* (Also changed the default avatars from 😐 to 😊 but that was just to see some smiles as I logged in). Some other aesthetic modifications have been made as well, mainly through the templates, forms and *style.css*.
* I've implemented some validations for user input when editing the profile (see `user.py`). In order to restrict and validate the user's **about** section, I created a function `check_about()` which restricts this field to between 3-300 characters. This may need to be restricted further in terms of what it should be allowed to contain. In order to validate the user's **favourite color**, I created a validation function `check_color()`. This function returns `True` if the input user provided actually is a color, and subsequently update their profile. If the color does **not** exist, they receive the flash message **Invalid color.**. These checks are performed in `my_profile()`. 




# 3A

## Peer review

Peer Review: daniel.johannessen_headbook

### Testing

Running an automated scan using OWASP’s ZAP security testing tool with the ajax spider, I receive alerts pointing out the following possible vulnerabilities:

1. **CSP: Wildcard Directive/Content Security Policy (CSP) Header Not Set**

Risk level: __Medium__

Both of these alerts point to the fact that the CSP header has not been set properly (this has been pointed out by the developer in their analysis of their own application).


2. **Missing Anti-clickjacking Header**

Risk level: __Medium__	

This is also something that can be mitigated using a CSP header with ‘frame-ancestors’ directive (or, as mentioned by ZAP, X-Frame-Options set to ‘DENY’).


3. **Cookie without SameSite Attribute**
	
Risk level: __Low__ 

The session cookie has not been set with a SameSite attribute, which inflicts risk of CSRF. SameSite attribute should be set to either Lax or Strict in order to mitigate this.

4. **Server Leaks Version Information via «Server» http Response Header Field**

Risk level: __Low__

Version information (Werkzeug/3.0.0 Python/3.11.4) is present in the “Server” header. ZAP suggests that the header should be supressed, or only provide generic details.


5. **X-Content-Type-Options Header Missing**

Risk level: __Low__	

ZAP suggests setting Content-Type header to ‘nosniff’ in order to mitigate risk of MIME-sniffing on the response body.


### Functionality

* The user is forced to update their password every time they change their profile.
* Stylesheet and profile pictures not accessible due to restrictive CSP header (good for security, bad for functionality). However, the developer is aware of this and stated it in their report (I had the same issue myself, so I sympathize).

### Security

* Internal server error when attempting to insert `<img src="" onerror=alert('hacked!')>` into ‘About’ field. This indicates that an attacker actually is affecting the program somehow by inserting malicious code into user input even though, thankfully, the alert is never executed.

* The developer has added some demands for passwords, i.e. a minimum length of 8, and at least one capitalized letter. In order to increase the integrity of the application, these demands could be a bit more restrictive, e.g. disallow sequential or repeated characters, in compliance with the NIST guidelines for secure passwords.

* The config file secrets is not included in .gitignore as stated in the report (but this may have been done intentionally in order to give me or the TA’s grading the project access?)

* The session cookie has not been set, and so the SameSite attribute has not been set either. 


### Summary

All in all I think the developer has done a good job to further secure the application in the following ways:

- Used prepared statements to prevent SQL injection
- Used muhtml to fix code injection issue
- Implemented hashing with salt of passwords
- Pointed out that users cannot change passwords to an empty one, but that you can add a user with no password
- Added validators for password demands 
- Added CSRF protection

They seem to be aware of some of the shortcomings that were left out or not implemented for other reasons.




# 3B

In order to further improve the app in regards to both in functionality and security I have implemented the following changes since the first hand-in:


### **Further validation of user input in profile**

Moved the validators for the profile form to a new module `validator.py`, and added a new validator for birthdate, which now requires user to be between 12-117 years old. Users are required to update this field if they edit their profile and it is left blank.
Previously the errors with input were displayed as flash messages, but now all of them appear as `ValidationErrors` next to the input field instead for better consistency. 



### **CSRF token**

Created a CSRF-token in app.py through the `flask_wtf.csrf` library's `CSRFProtect`. According to documentation, this should ensure that the token is applied on all routes. The token is used on requests in the login- and profile forms.



### **Modified Response Headers**

ZAP analysis pointed out the risk of MIME sniffing attacks, as well as clickjacking attempts. I've implemented a CSP header with a nonce value set in `before_request` to allow content with the matching nonce only. I also set the X-Content-Type-Options header to 'nosniff', and set X-Frame-Options to 'DENY' in order to protect against clickjacking attempts.


```sh
@app.before_request
def before_request():
    g.csp_nonce = secrets.token_urlsafe(32)

@app.after_request
def after_request(response):
    # get nonce
    n = g.csp_nonce
    # define csp header
    # TODO: fix style-src, currently not secure
    head = f"default-src 'self'; script-src 'self' 'nonce-{n}'; style-src 'self' 'unsafe-inline'; img-src 'self' https://* 'nonce-{n}'" 
    response.headers["Content-Security-Policy"] = head
    # to avoid MIME sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # to avoid clickjacking attempts
    response.headers['X-Frame-Options'] = 'DENY'
    return response
```


Now the scripts loaded are demanded to stem from the source origin, and images can only be loaded from https-domains. However, I am yet to figure out how to load styles from the stylesheet without 'unsafe-inline', which is not considered secure. The users template uses inline scripts, so without this value, the user's favorite color will be rendered blank. Allowing for `'unsafe-inline'` *is* a security risk.


### **SQL Injection**

ZAP was able to perform SQL injection through the profile picture URL field in the user profile. This seems to have been mitigated through use of a CSP header.


### **Additional modifications**

- Ignore case of username input when logging in.
- Added the Jinja2 attribute `|e` to user controlled values in templates in order to properly escape the input, and further reduce risk of XSS-attacks.
- In the login template, I changed the /login/ path to use the flask function `url_for('login')` to generate the path to login dynamically, instead of directly exposing it.


**After implementing these changes, the only significant alerts I receive from security testing tools is problems with my CSP-header, i.e. the use of `unsafe-inline`. I have not found a way around this as of yet.**







# Copyright

* `unknown.png` – from [OpenMoji](https://openmoji.org/about/) ([Attribution-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-sa/4.0/))
* `favicon.(png|ico)` – from [Game Icons](https://game-icons.net/1x1/skoll/knockout.html) ([CC BY 3.0](http://creativecommons.org/licenses/by/3.0/))
* `uhtml.js` – from [µHTML](https://github.com/WebReflection/uhtml) (Copyright (c) 2020, Andrea Giammarchi, [ISC License](https://opensource.org/license/isc-license-txt/))
* Base code by Anya
