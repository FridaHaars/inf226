import re
from flask import redirect, flash, request
from flask_login import current_user
from werkzeug.security import check_password_hash
'''
https://pages.nist.gov/800-63-3/sp800-63b.html
https://www.psmpartners.com/blog/nist-password-best-practices/#NIST_Password_Guidelines_for_2022
https://stackoverflow.com/questions/16709638/checking-the-strength-of-a-password-how-to-check-conditions#32542964

Password demands:
- Length 8-64 characters
- Upper- and lowercase letters
- Symbol
- Digit
'''


# function that checks the above requirements
def check_password(pw):
    length_error = len(pw) < 8 or len(pw) > 64
    digit_error = re.search(r'\d', pw) is None
    uppercase_error = re.search(r'[A-Z]', pw) is None
    lowercase_error = re.search(r'[a-z]', pw) is None
    symbol_error = re.search(r'\W', pw) is None
    password_ok = not (length_error or digit_error or
                       uppercase_error or lowercase_error or symbol_error)

    return {
        'password_ok': password_ok,
        'length_error': length_error,
        'digit_error': digit_error,
        'uppercase_error': uppercase_error,
        'lowercase_error': lowercase_error,
        'symbol_error': symbol_error,
    }


# if there is any violation of the password requirements, --
# -- the cause is output and the app redirects to start
def error_message(pw):
    check = check_password(pw)

    if check.get('length_error'):
        flash(f'Password must be between 8-64 characters.')
    if check.get('digit_error'):
        flash(f'Password must include at least one digit.')
    elif check.get('uppercase_error') or check.get('lowercase_error'):
        flash(f'Password must include both upper- and lowercase characters.')
    elif check.get('symbol_error'):
        flash(f'Password must include a symbol.')

    return redirect('/')


# helper for my_profile() - checks whether username/password is correct; --
# -- username correct and password incorrect; or whether user actually --
# -- exists in database.
def pw_validator(u, pw):
    isValid = False 
    if u and check_password_hash(u.password, pw):
        isValid = True 
    elif u and not check_password_hash(u.password, pw):
        isValid = False
    else:
        isValid = None
    return isValid