from flask_login import current_user, login_required, login_user
import os
import secrets
from datetime import date
from typing import Any
from flask import (Flask, abort, g, jsonify, redirect,
                   request, send_from_directory, render_template,
                   session, flash)
from .auth.password_check import *
from urllib.parse import urlparse
from .forms.login_form import LoginForm
from .forms.profile_form import ProfileForm
from .utils import *
from .user import *
from flask_wtf.csrf import CSRFProtect, generate_csrf
db = None


################################
# Set up app
APP_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(APP_PATH, "templates/"),
    static_folder=os.path.join(APP_PATH, "static/"),
)

# configure from secrets file
app.config.from_pyfile('secrets')
# create CSRF token
csrf = CSRFProtect(app)

# Add a login manager to the app
login_manager = flask_login.LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"




# This method is called whenever the login manager needs to get
# the User object for a given user id – for example, when it finds
# the id of a logged in user in the session data (session['_user_id'])
@login_manager.user_loader
def user_loader(user_id):
    return User.get_user(user_id)


#TODO: move routes
################################
# ROUTES – these get called to handle requests
#
#    Before we get this far, Flask has set up a session store with a session cookie, and Flask-Login
#    has dealt with authentication stuff (for routes marked `@login_required`)
#
#    Request data is available as global context variables:
#      * request – current request object
#      * session – current session (stores arbitrary session data in a dict-like object)
#      * g – can store whatever data you like while processing the current request
#      * current_user – a User object with the currently logged in user (if any)


@app.get("/")
@app.get("/index.html.j2")
@login_required
def index_html():
    """Render the home page"""

    return render_template("home.html.j2")


# by default, path parameters (filename, ext) match any string not including a '/'
@app.get("/<filename>.<ext>")
def serve_static(filename, ext):
    """Serve files from the static/ subdirectory"""

    # browsers can be really picky about file types, so it's important
    # to set this correctly, particularly for JS and CSS
    file_types = {
        "js": "application/javascript",
        "ico": "image/vnd.microsoft.icon",
        "png": "image/png",
        "html": "text/html",
        "css": "text/css",
    }

    if ext in file_types:
        return send_from_directory(
            app.static_folder, f"{filename}.{ext}", mimetype=file_types[ext]
        )
    else:
        abort(404)

# to log user attempts at logging in
attempts = 0
@app.route("/login/", methods=["GET", "POST"])
def login():
    # Global variable to keep track of number of unsuccessful login attempts
    global attempts

    """Render (GET) or process (POST) login form"""
    debug('/login/ – session:', session, request.host_url)
    form = LoginForm()

    if not form.next.data:
        # set 'next' field from URL parameters
        form.next.data = request.args.get("next")

    if form.is_submitted():
        debug(
            f'Received form:\n    {form.data}\n{"INVALID" if not form.validate() else "valid"} {form.errors}'
        )

        if form.validate():
            # ignore the case of username (e.g. BoB==bob)
            username = form.username.data.lower()
            password = form.password.data
            user = user_loader(username)

            # check if the user exists and the password is correct
            if pw_validator(user, password):
                # automatically set the logged-in session cookie
                login_user(user)
                flash(f"User {user.username} logged in successfully.")
                return safe_redirect_next()

            # user exists but password is wrong
            elif pw_validator(user, password) == False:
                attempts += 1

                # check if user has tried and failed 3 times. If so, display the contents --
                # -- of too_many_attempts, i.e. suspend login attempts for 30 seconds
                if attempts >= 3:
                    attempts = 0
                    return render_template("login.html.j2", form=form, too_many_attempts=True)

                flash("Incorrect password.")

            # user not in database
            elif pw_validator(user, password) == None:
                flash("User does not exist.")

    return render_template("login.html.j2", form=form, too_many_attempts=False)


@app.get('/logout/')
def logout_gitlab():
    print('logout', session, session.get('access_token'))
    flask_login.logout_user()
    return redirect('/')


@app.route("/profile/", methods=["GET", "POST", "PUT"])
@login_required
def my_profile():
    """Display or edit user's profile info"""
    debug("/profile/ – current user:", current_user, request.host_url)

    form = ProfileForm()
    if form.is_submitted():
        debug(
            f'Received form:\n    {form.data}\n    {f"INVALID: {form.errors}" if not form.validate() else "ok"}'
        )
        if form.validate():
            if form.password.data:  # change password if user set it
                # check whether the proposed password is a valid one
                if (check_password(form.password.data).get('password_ok')):
                    current_user.password = form.password.data
                else:
                    # if proposed password invalid, inform of its shortcomings
                    error_message(form.password.data)

            if form.birthdate.data:  # change birthday if set
                current_user.birthdate = form.birthdate.data.isoformat()
            
            if form.color.data:  # change color if set
                current_user.color = form.color.data
            
            if form.picture_url.data:  # change if picture_url is set
                current_user.picture_url = form.picture_url.data
            
            if form.about.data:  # change about if set
                current_user.about = form.about.data

            current_user.save()
        
        else:
            pass  # The profile.html template will display any errors in form.errors
   
    else:  # fill in the form with the user's info
        form.username.data = current_user.username
        form.password.data = ""
        form.password_again.data = ""
        # only set this if we have a valid date
        form.birthdate.data = current_user.get("birthdate") and date.fromisoformat(
            current_user.get("birthdate")
        )
        form.color.data = current_user.get("color", "")
        form.picture_url.data = current_user.get("picture_url", "")
        form.about.data = current_user.get("about", "")

    return render_template("profile.html.j2", form=form, user=current_user)



'''Users who are not buddies cannot see the other user's information, only their name. '''
@app.get("/users/")
@login_required
def get_users():
    sql = "SELECT id, username FROM users;"
    rows = sql_execute(sql).fetchall()

    result = []
    # add current user to home page
    result.append(dict(current_user))
    for row in rows:
        user = User({"id": row[0], "username": row[1]})
        # if the user is buds with the current user, add them to result. --
        # -- If not, add the current user and only the other user's username. --
        # -- The user(s) in result are the only one(s) to be displayed at home page.
        if user != current_user:
            if is_buddies(current_user.id, user.id):
                result.append(user)
            else:
                non_buddy_users = [User({"username": user.username})]
                result.extend(non_buddy_users)

    if prefers_json():
        return jsonify(result)
    else:
        return render_template("users.html.j2", users=result)



''' Users can now only see their own info or buddies info through /users/*.
If they attempt to view the info of a non-buddy, they receive a prompt
'You are not buds with this user!'. '''
@app.get("/users/<userid>")
@login_required
def get_user(userid):
    if userid == 'me':
        u = current_user
    else:
        u = User.get_user(userid)

    if u:
        del u["password"]  # hide the password, just in case
        # check if buddies
        if u == current_user or is_buddies(current_user.id, u.id):
            if prefers_json():
                return jsonify(u)
            else:
                return render_template("users.html.j2", users=[u])
        else:
            return 'You are not buds with this user!'
    else:
        abort(404)


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




def get_safe_redirect_url():
    # see discussion at
    # https://stackoverflow.com/questions/60532973/how-do-i-get-a-is-safe-url-function-to-use-with-flask-and-how-does-it-work/61446498#61446498
    next = request.values.get('next')
    if next:
        url = urlparse(next)
        if not url.scheme and not url.netloc:  # ignore if absolute url
            return url.path   # use only the path
    return None


def safe_redirect_next():
    next = get_safe_redirect_url()
    return redirect(next or '/')

# For full RFC2324 compatibilty


@app.get("/coffee/")
def nocoffee():
    abort(418)


@app.route("/coffee/", methods=["POST", "PUT"])
def gotcoffee():
    return "Thanks!"


################################
# For database access
@app.teardown_appcontext
def teardown_db(exception):
    cursor = g.pop("cursor", None)

    if cursor is not None:
        cursor.close()


with app.app_context():
    sql_init()

    
