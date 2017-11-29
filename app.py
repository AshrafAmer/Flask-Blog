from flask import Flask, render_template, flash, redirect, request, url_for, session, logging
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps


app = Flask(__name__)


# MySQL config
app.config['MYSQL_HOST'] = '-- --'
app.config['MYSQL_USER'] = '-- --'
app.config['MYSQL_PASSWORD'] = '-- --'
app.config['MYSQL_DB'] = '-- --'
app.config['MYSQL_CURSORCLASS'] = '-- --'


#MySQL init
mysql = MySQL(app)


@app.route('/')
def index():
    return render_template('home.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/articles')
def articles():
    cur = mysql.connection.cursor()
    results = cur.execute("SELECT * FROM articles")
    articles = cur.fetchall()
    if results > 0:
        return render_template('articles.html', articles = articles)
    else:
        msg = 'NO articles added yet'
        return render_template('articles.html', msg = msg)

    cur.close()



@app.route('/article/<string:id>/')
def article(id):
    cur = mysql.connection.cursor()
    results = cur.execute("SELECT * FROM articles WHERE id = %s", [id])
    article = cur.fetchone()

    return render_template('article.html', article = article)

    cur.close()


class RegisterForm(Form):
    name = StringField('Name', [validators.length(min = 1, max = 50)])
    username = StringField('Username', [validators.length(min = 4, max = 25)])
    email = StringField('Email', [validators.length(min = 6, max = 50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message = 'Password DO NOT match')
    ])
    confirm = PasswordField('Confirm Password')


@app.route('/register', methods = ['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # Cursor..
        cur = mysql.connection.cursor()

        # Execute Queries..
        cur.execute(
            "INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)",
            (name, email, username, password)
            )

        # Save DB.. (commit and close DB)
        mysql.connection.commit()
        cur.close()

        # show msg to users if successful
        flash('You are now successfully registered', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form = form)


@app.route('/login', methods = ['GET', 'POST'])
def login ():
    if request.method == 'POST':
        username = request.form['username']
        password_candidate = request.form['password']

        #Cursor..
        cur = mysql.connection.cursor()
        result = cur.execute(
            "SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            # fetch stored data - hash
            sqldata = cur.fetchone()
            password = sqldata['password']
            # Compare the password entered
            if sha256_crypt.verify(password_candidate, password):
                # Login..
                session['logged_in'] = True
                session['username'] = username

                flash('You are successfully logged in', 'success')

                return redirect(url_for('dashboard'))
            else:
                error = 'password or username do not match'
                return render_template('login.html', error = error)
            cur.close()
        else:
            error = 'username not found'
            return render_template('login.html', error = error)

    return render_template('login.html')


# Checked if log in
def is_logged_in(l):
    @wraps(l)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return l(*args, **kwargs)
        else:
            flash('Please login', 'danger')
            return redirect(url_for('login'))
    return wrap


# LogOut..
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


# Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    cur = mysql.connection.cursor()
    results = cur.execute("SELECT * FROM articles")
    articles = cur.fetchall()
    if results > 0:
        return render_template('dashboard.html', articles = articles)
    else:
        msg = 'NO articles added yet'
        return render_template('dashboard.html', msg = msg)

    cur.close()


# Article Form Class..
class ArticleForm(Form):
    title = StringField('Title', [validators.length(min = 1, max = 250)])
    body = TextAreaField('Body', [validators.length(min = 30)])


# Article Route
@app.route('/add_article', methods = ['GET', 'POST'])
@is_logged_in
def add_article():
    form = ArticleForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        body = form.body.data
        cur = mysql.connection.cursor()
        # Execute Queries
        cur.execute("INSERT INTO articles (title, body, author) VALUES (%s, %s, %s)",
            (title, body, session['username']))
        # commit
        mysql.connection.commit()
        cur.close()
        flash('Article Created', 'success')

        return redirect(url_for('dashboard'))

    return render_template('add_article.html', form = form)


@app.route('/edit_article/<string:id>', methods = ['GET', 'POST'])
@is_logged_in
def edit_article(id):
    cur = mysql.connection.cursor()
    # Execute Queries
    result = cur.execute("SELECT * FROM articles WHERE id = %s", [id])
    article = cur.fetchone()
    # GET Form and SET data
    form = ArticleForm(request.form)
    form.title.data = article['title']
    form.body.data = article['body']

    if request.method == 'POST' and form.validate():
        title = request.form['title']
        body = request.form['body']
        cur = mysql.connection.cursor()
        # Execute Queries
        cur.execute("UPDATE articles SET title = %s, body = %s WHERE id = %s", (title, body, id))
        # commit
        mysql.connection.commit()
        cur.close()
        flash('Article Updated', 'success')

        return redirect(url_for('dashboard'))

    return render_template('edit_article.html', form = form)


# Delete Article
@app.route('/delete_article/<string:id>', methods = ['POST'])
@is_logged_in
def delete_article(id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM articles WHERE id = %s", [id])
    mysql.connection.commit()
    cur.close()
    flash('Article Deleted', 'success')
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.secret_key = 'SecrEt+2'
    app.run(debug=True)
