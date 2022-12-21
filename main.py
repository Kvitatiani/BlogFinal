from flask import Flask, render_template, redirect, url_for, flash, abort, g
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)


##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# Load users
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Gravatars for users.
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


##CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    # Adding child(BlogPost) to the user
    posts = relationship("BlogPost", back_populates="author")
    # Adding another child(Comment) to the user
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    # Child to parent relationship
    # Create Foreign Key, "users.id" - the users refers to tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the user object, the "posts" refers to the posts property in the User class.
    author = relationship("User", back_populates="posts")
    # Parent to child relationship
    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    # Child to parent relationship(User)
    # Create foreign key "users.id" - the users refer to the tablename of User
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the user subject, the "comments" refers to the comments property of the User class.
    comment_author = relationship("User", back_populates="comments")
    # Child to parent relationship(BlogPost)
    # Adding another foreign key
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    # adding reference to the post object, the "comments" refers to the comments property of the BlogPost class.
    parent_post = relationship("BlogPost", back_populates="comments")


def admin_only(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.id != 1:
            abort(403)
        return func(*args, **kwargs)
    return wrapper


with app.app_context():
    db.create_all()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    # Get the data from WTForm
    form = RegisterForm()
    email = form.email.data
    password = form.password.data
    name = form.name.data
    user = User.query.filter_by(email=email).first()

    if form.validate_on_submit():
        if user:
            # If user already exists, they will be redirected to login page
            # and get a flash message indicating the error.
            flash("You've already signed up with that email, please log in instead.")
            return redirect(url_for('login'))
        else:
            # If submitted, hash and salt user's password and add it to the database
            hashed_and_salted_password = generate_password_hash(
                password=password,
                method='pbkdf2:sha256',
                salt_length=8
            )
            new_user = User(
                email=email,
                password=hashed_and_salted_password,
                name=name
            )
            db.session.add(new_user)
            db.session.commit()

            # Log in user
            login_user(new_user)

            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    email = form.email.data
    password = form.password.data
    user = User.query.filter_by(email=email).first()

    # Check whether the email and password exist in the database,
    # if not - flash messages, if all is good - login user.
    if form.validate_on_submit():
        if not user:
            flash("The email doesn't exist, please try again.")
        elif not check_password_hash(user.password, password):
            flash("Password is incorrect, please try again.")
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login to add a comment.")
            return redirect(url_for('login'))

        new_comment = Comment(
            text=form.comment.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
    return render_template("post.html", post=requested_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>", methods=['GET', 'POST'])
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
