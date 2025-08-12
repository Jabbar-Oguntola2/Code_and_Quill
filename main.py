from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
ckeditor = CKEditor(app)
Bootstrap5(app)


gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None
                    )


login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, int(user_id))


# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///posts.db")
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CONFIGURE TABLES
## creating a One(Author) to Many(Books) Database
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    author = relationship("User", back_populates="blogs")
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)


    #relationship between blog post table and comments
    blog_comments = relationship("Comment", back_populates="blog_post", cascade="all, delete-orphan")



class User(db.Model, UserMixin):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    blogs = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="blog_poster")
    email: Mapped[str] = mapped_column(String(250), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(250), nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)

class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # relationship between Comments and User
    poster_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    blog_poster = relationship("User", back_populates="comments")
    text: Mapped[str] = mapped_column(Text, nullable=False)

    ## relationship between Comment and Blog posts
    post_id: Mapped[int] = mapped_column(Integer, ForeignKey("blog_posts.id"))
    blog_post = relationship("BlogPost", back_populates="blog_comments")



with app.app_context():
    db.create_all()


def admin_checker():
    try:
        current_id = current_user.id
        return True if current_id == 1 else False
    except AttributeError:
        return False



def website_permission(function):
    @wraps(function)
    def checker(*args, **kwargs):
        if not admin_checker():
            return app.aborter(403)
        return function(*args, **kwargs)
    return checker




@app.route('/register', methods=["GET", "POST"])
def register():
    registration = RegisterForm()
    if registration.validate_on_submit():
        name = registration.name.data
        email = registration.email.data
        protected_password = generate_password_hash(password=registration.password.data, method='pbkdf2:sha256', salt_length=8)

        existing_user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        if existing_user:
            flash(message="This email is already being used.")
            return redirect(url_for('register'))
        else:
            new_user = User(
                email=email,
                name=name,
                password=protected_password,
            )

            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=registration)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        password = login_form.password.data

        existing_user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        if not existing_user:
            flash(message="Incorrect email or password.")
            return redirect(url_for('login'))
        else:
            correct_password = check_password_hash(existing_user.password, password)
            if not correct_password:
                flash(message="Incorrect email or password.")
                return redirect(url_for('login'))
            else:
                login_user(existing_user)
                return redirect(url_for('get_all_posts'))



    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts, is_admin=admin_checker())


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = db.get_or_404(BlogPost, post_id)
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("Sorry you need to be logged in to comment.")
            return redirect(url_for("login"))
        else:
            new_comment = Comment(
                blog_poster = current_user,
                text= comment_form.comment.data,
                blog_post=requested_post,

            )

            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("show_post", post_id=post_id))
    return render_template("post.html", post=requested_post, is_admin=admin_checker(), form=comment_form)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@website_permission
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


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@website_permission
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@website_permission
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=False)
