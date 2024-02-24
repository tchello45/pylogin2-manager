from flask import Flask, render_template, request, redirect, url_for, flash, session
import json
import os
import requests as req

if not os.path.exists('data/pylogin2.conf'):
    raise Exception('Config file not found: pylogin2.conf')
with open('data/pylogin2.conf') as f:
    config = json.load(f)
    try:
        pylogin2_host = config['pylogin2_host']
        pylogin2_port = config['pylogin2_port']
    except:
        raise Exception('Config file is not valid')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'my secret key'

def get_username(token:str):
    headers = {'Authorization': 'Bearer '+token}
    r = req.get('http://'+pylogin2_host+':'+pylogin2_port+'/web/dev_alpha/token', headers=headers)
    if r.status_code == 200:
        pass
    else:
        print(r.text, "get_username")
        return r.json()["current_user"]
def get_user(token:str, username:str=None):
    data = {}
    if username:
        data = {'username': username}
    headers = {'Authorization': 'Bearer '+token}
    r = req.get('http://'+pylogin2_host+':'+pylogin2_port+'/web/dev_alpha/user', headers=headers, json=data)
    if r.status_code == 200:
        return r.json()
    else:
        print(r.text, "get_user")
        return r.json()


@app.route('/')
def index():
    if 'token' in session:
        return redirect(url_for('home'))
    else:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        req_data = {'username': username, 'password': password, 'restricted_mode_allowed': True}
        r = req.post('http://'+pylogin2_host+':'+pylogin2_port+'/web/dev_alpha/token', json=req_data)
        if r.status_code == 200:
            token = r.json()['token']
            session['token'] = token
            restricted_mode = r.json().get('restricted_mode', False)
            if restricted_mode:
                flash('Restricted mode', category='warning')
            return redirect(url_for('home'))
        else:
            flash(r.json()['msg'], category='error')
        
    return render_template('home/login.html')
@app.route('/logout')
def logout():
    session.pop('token', None)
    return redirect(url_for('login'))
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form.get('email', None)
        registration_password = request.form.get('registration_password', None)
        data = {'username': username, 'password': password, 'email': email, 'registration_password': registration_password}
        if not email:
            data.pop('email')
        if not registration_password:
            data.pop('registration_password')
        r = req.post('http://'+pylogin2_host+':'+pylogin2_port+'/dev_alpha/registration', json=data)
        if r.status_code == 200:
            flash('Account created', category='success')
            return redirect(url_for('login'))
        elif r.status_code == 201:
            return redirect(url_for('verify'))
        else:
            flash(r.json()['msg'], category='error')
    return render_template('home/signup.html')
@app.route('/home', methods=['GET', 'POST'])
def home():
    if 'token' in session:
        token = session['token']
        username = get_username(token)
        if request.method == 'POST':
            email = request.form['email']
            data = {'email': email}
            headers = {'Authorization': 'Bearer '+token}
            r = req.put('http://'+pylogin2_host+':'+pylogin2_port+'/web/dev_alpha/user', headers=headers, json=data)
            if r.status_code == 200:
                flash('Email updated', category='success')
            else:
                flash(r.json()['msg'], category='error')
        user = get_user(token, username)
        return render_template('home/home.html', user=user)
    else:
        return redirect(url_for('login'))
@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if "token" in session:
        token = session['token']
        username = get_username(token)
        if request.method == 'POST':
            email_token = request.form['token']
            data = {'username': username, 'token': email_token}
            headers = {'Authorization': 'Bearer '+token}
            r = req.put('http://'+pylogin2_host+':'+pylogin2_port+'/dev_alpha/registration', json=data, headers=headers)
            if r.status_code == 200:
                flash('Account verified', category='success')
                return redirect(url_for('login'))
            else:
                flash(r.json()['msg'], category='error')
        return render_template('home/verify_email_token.html')
    else:
        return redirect(url_for('login'))
@app.route('/request_email_token', methods=['GET', 'POST'])
def request_email_token():
    if "token" in session:
        token = session['token']
        username = get_username(token)
        user = get_user(token, username)
        if request.method == 'POST':
            email = request.form['email']
            data = {'username': username, 'email': email}
            headers = {'Authorization': 'Bearer '+token}
            r = req.put('http://'+pylogin2_host+':'+pylogin2_port+'/web/dev_alpha/user', json=data, headers=headers)
            if r.status_code == 200:
                r = req.get('http://'+pylogin2_host+':'+pylogin2_port+'/dev_alpha/registration', headers=headers)
                if r.status_code == 200:
                    flash('Email token sent', category='success')
                else:
                    flash(r.json()['msg'], category='error')
            else:
                flash(r.json()['msg'], category='error')
        
        return render_template('home/send_email_token.html', user=user)
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if "token" in session:
        token = session['token']
        username = get_username(token)
        user = get_user(token, username)
        if request.method == 'POST':
            old_password = request.form['old_password']
            password = request.form['password']
            data = {'username': username, 'old_password': old_password, 'password': password}
            headers = {'Authorization': 'Bearer '+token}
            r = req.put('http://'+pylogin2_host+':'+pylogin2_port+'/web/dev_alpha/user', json=data, headers=headers)
            if r.status_code == 200:
                flash('Password changed', category='success')
            else:
                flash(r.json()['msg'], category='error')
        return render_template('home/change_password.html', user=user)
    else:
        return redirect(url_for('login'))




@app.route('/admin')
def admin():
    if 'token' in session:
        token = session['token']
        username = get_username(token)
        user = get_user(token, username)
        if user['role'] == 'common':
            return redirect(url_for('home'))
        headers = {'Authorization': 'Bearer '+token}
        r = req.get('http://'+pylogin2_host+':'+pylogin2_port+'/dev_alpha/info')
        version = r.json()['version']
        r = req.get('http://'+pylogin2_host+':'+pylogin2_port+'/web/dev_alpha/users', headers=headers)
        user_count = r.text
        return render_template('admin/home.html', user=user, version=version, user_count=user_count)
    else:
        return redirect(url_for('login'))
@app.route('/create_user', methods=['GET', 'POST'])
def create_user():
    if 'token' in session:
        token = session['token']
        username = get_username(token)
        user = get_user(token, username)
        if user['role'] == 'common':
            return redirect(url_for('home'))
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            email = request.form.get('email', None)
            role = request.form.get('role', None)
            data = {'username': username, 'password': password, 'email': email, 'role': role}
            if not email:
                data.pop('email')
            if not role:
                data.pop('role')
            headers = {'Authorization': 'Bearer '+token}
            r = req.post('http://'+pylogin2_host+':'+pylogin2_port+'/web/dev_alpha/user', json=data, headers=headers)
            if r.status_code == 200:
                flash('User created', category='success')
            else:
                flash(r.json()['msg'], category='error')
        return render_template('admin/createUser.html', user=user)
    else:
        return redirect(url_for('login'))
@app.route('/modify_user', methods=['GET', 'POST'])
def modify_user():
    if 'token' in session:
        token = session['token']
        username = get_username(token)
        user = get_user(token, username)
        if user['role'] == 'common':
            return redirect(url_for('home'))
        if request.method == 'POST':
            if 'delete' in request.form:
                username = request.form['username']
                headers = {'Authorization': 'Bearer '+token}
                r = req.delete('http://'+pylogin2_host+':'+pylogin2_port+'/web/dev_alpha/user', json={'username': username}, headers=headers)
                if r.status_code == 200:
                    flash('User deleted', category='success')
                else:
                    flash(r.json()['msg'], category='error')
            else:
                username = request.form['username']
                password = request.form.get('password', None)
                email = request.form.get('email', None)
                role = request.form.get('role', None)
                allow_web_login = request.form.get('allow_web_login', False)
                allow_api_login = request.form.get('allow_api_login', False)
                allow_system_login = request.form.get('allow_system_login', False)
                email_verified = request.form.get('email_verified', False)
                data = {'username': username, 'password': password, 'email': email, 'role': role, 'allow_web_login': allow_web_login, 'allow_api_login': allow_api_login, 'allow_system_login': allow_system_login, 'email_verified': email_verified}
                if not email:
                    data.pop('email')
                if not role:
                    data.pop('role')
                if not password:
                    data.pop('password')
                headers = {'Authorization': 'Bearer '+token}
                r = req.put('http://'+pylogin2_host+':'+pylogin2_port+'/web/dev_alpha/user', json=data, headers=headers)
                if r.status_code == 200:
                    flash('User modified', category='success')
                else:
                    flash(r.json()['msg'], category='error')
        return render_template('admin/modifyUser.html')
    else:
        return redirect(url_for('login'))
@app.route('/modify_user/<target_username>', methods=['GET', 'POST'])
def modify_set_user(target_username):
    if 'token' in session:
        token = session['token']
        username = get_username(token)
        user = get_user(token, username)
        if user['role'] == 'common':
            return redirect(url_for('home'))
        if request.method == 'POST':
            if 'delete' in request.form:
                username = request.form['username']
                headers = {'Authorization': 'Bearer '+token}
                r = req.delete('http://'+pylogin2_host+':'+pylogin2_port+'/web/dev_alpha/user', json={'username': username}, headers=headers)
                if r.status_code == 200:
                    flash('User deleted', category='success')
                else:
                    flash(r.json()['msg'], category='error')
            else:
                username = request.form['username']
                password = request.form.get('password', None)
                email = request.form.get('email', None)
                role = request.form.get('role', None)
                allow_web_login = request.form.get('allow_web_login', False)
                allow_api_login = request.form.get('allow_api_login', False)
                allow_system_login = request.form.get('allow_system_login', False)
                email_verified = request.form.get('email_verified', False)
                data = {'username': username, 'password': password, 'email': email, 'role': role, 'allow_web_login': allow_web_login, 'allow_api_login': allow_api_login, 'allow_system_login': allow_system_login, 'email_verified': email_verified}
                if not email:
                    data.pop('email')
                if not role:
                    data.pop('role')
                if not password:
                    data.pop('password')
                headers = {'Authorization': 'Bearer '+token}
                r = req.put('http://'+pylogin2_host+':'+pylogin2_port+'/web/dev_alpha/user', json=data, headers=headers)
                if r.status_code == 200:
                    flash('User modified', category='success')
                else:
                    flash(r.json()['msg'], category='error')
        target = get_user(token, target_username)
        return render_template('admin/modify_set_user.html', user=target)
    else:
        return redirect(url_for('login'))
@app.route('/settings', methods=['POST', 'GET'])
def settings():
    if 'token' in session:
        token_ = session['token']
        user_ = get_user(token_)
        if user_['allow_api_login'] == False:
            return redirect(url_for('home'))
    else:
        return redirect(url_for('login'))
    if request.method == 'POST':
        if 'update' in request.form:
            registration_enabled = request.form.get('registration_enabled', False)
            default_active = request.form.get('default_active', False)
            default_allow_web_login = request.form.get('default_allow_web_login', False)
            default_allow_api_login = request.form.get('default_allow_api_login', False)
            default_allow_system_login = request.form.get('default_allow_system_login', False)
            default_role = request.form.get('default_role', None)
            data = {'registration_enabled': registration_enabled, 'default_active': default_active, 'default_allow_web_login': default_allow_web_login, 'default_allow_api_login': default_allow_api_login, 'default_allow_system_login': default_allow_system_login, 'default_role': default_role}
            if not default_role:
                data.pop('default_role')
            headers = {'Authorization': 'Bearer '+token_}
            r = req.put('http://'+pylogin2_host+':'+pylogin2_port+'/api/dev_alpha/settings', headers=headers, json=data)
            if r.status_code == 200:
                flash('Settings updated successfully', 'success')
                headers = {'Authorization': 'Bearer '+token_}
                r = req.get('http://'+pylogin2_host+':'+pylogin2_port+'/api/dev_alpha/settings', headers=headers)
                settings_ = r.json()
                return render_template('admin/settings.html', settings=settings_)
            else:
                flash(r.json()["msg"], 'error')
                headers = {'Authorization': 'Bearer '+token_}
                r = req.get('http://'+pylogin2_host+':'+pylogin2_port+'/api/dev_alpha/settings', headers=headers)
                settings_ = r.json()
                return render_template('admin/settings.html', settings=settings_)
        if 'update_password' in request.form:
            registration_password = request.form.get('registration_password', "")
            data = {'registration_password': registration_password}
            headers = {'Authorization': 'Bearer '+token_}
            r = req.put('http://'+pylogin2_host+':'+pylogin2_port+'/api/dev_alpha/settings', headers=headers, json=data)
            if r.status_code == 200:
                flash('Settings updated successfully', 'success')
                headers = {'Authorization': 'Bearer '+token_}
                r = req.get('http://'+pylogin2_host+':'+pylogin2_port+'/api/dev_alpha/settings', headers=headers)
                settings_ = r.json()
                return render_template('admin/settings.html', settings=settings_)
            else:
                flash(r.json()["msg"], 'error')
                headers = {'Authorization': 'Bearer '+token_}
                r = req.get('http://'+pylogin2_host+':'+pylogin2_port+'/api/dev_alpha/settings', headers=headers)
                settings_ = r.json()
                return render_template('admin/settings.html', settings=settings_)
        if 'update_email_settings' in request.form:
            email_verification_required = request.form.get('email_verification_required', False)
            email_verification_force = request.form.get('email_verification_force', False)
            data = {'verified_email_required': email_verification_required, 'email_verification_force': email_verification_force}
            headers = {'Authorization': 'Bearer '+token_}
            r = req.put('http://'+pylogin2_host+':'+pylogin2_port+'/api/dev_alpha/settings', headers=headers, json=data)
            if r.status_code == 200:
                flash('Settings updated successfully', 'success')
                headers = {'Authorization': 'Bearer '+token_}
                r = req.get('http://'+pylogin2_host+':'+pylogin2_port+'/api/dev_alpha/settings', headers=headers)
                settings_ = r.json()
                return render_template('admin/settings.html', settings=settings_)
            else:
                flash(r.json()["msg"], 'error')
                headers = {'Authorization': 'Bearer '+token_}
                r = req.get('http://'+pylogin2_host+':'+pylogin2_port+'/api/dev_alpha/settings', headers=headers)
                settings_ = r.json()
                return render_template('admin/settings.html', settings=settings_)
    else:
        headers = {'Authorization': 'Bearer '+token_}
        r = req.get('http://'+pylogin2_host+':'+pylogin2_port+'/api/dev_alpha/settings', headers=headers)
        settings_ = r.json()
        print(settings_)
        return render_template('admin/settings.html', settings=settings_)

if __name__ == '__main__':
    app.run(debug=True, port=5001)