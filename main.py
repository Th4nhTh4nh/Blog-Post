from datetime import date
from typing import List
from flask import Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm


class Base(DeclarativeBase):
    pass


app = Flask(__name__)
app.config["SECRET_KEY"] = "8BYkEfBA6O6donzWlSihBXox7C0sKR6b"
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login


# CONNECT TO DB
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///posts.db"
db = SQLAlchemy(model_class=Base)
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)


gravatar = Gravatar(
    app,
    size=100,
    rating="g",
    default="retro",
    force_default=False,
    force_lower=False,
    use_ssl=False,
    base_url=None,
)


# TODO: Create a User table for all your registered users.
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String)
    email: Mapped[str] = mapped_column(String, unique=True)
    password: Mapped[str] = mapped_column(String)

    posts: Mapped[List["BlogPost"]] = relationship(back_populates="author")
    user_comments: Mapped[List["Comment"]] = relationship(back_populates="owner")


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    author: Mapped["User"] = relationship(back_populates="posts")

    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[Text] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)

    blog_comments: Mapped[List["Comment"]] = relationship(back_populates="blog")


class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[Text] = mapped_column(Text, nullable=False)

    owner_id: Mapped["User"] = mapped_column(ForeignKey("users.id"))
    owner: Mapped["User"] = relationship(back_populates="user_comments")

    blog_id: Mapped["BlogPost"] = mapped_column(ForeignKey("blog_posts.id"))
    blog: Mapped["BlogPost"] = relationship(back_populates="blog_comments")


with app.app_context():
    db.create_all()


def admin_only(f):
    @wraps(f)
    def decorator_function(*args, **kwargs):
        if current_user != 1:
            return abort(403)
        return f(*args, **kwargs)

    return decorator_function


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        encrypt_password = generate_password_hash(
            form.password.data, method="pbkdf2:sha256", salt_length=8
        )
        email_check = db.session.execute(
            db.select(User).where(User.email == email)
        ).scalar()
        if not email_check:
            new_user = User(
                email=form.email.data, password=encrypt_password, name=form.name.data
            )
            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)
            return redirect(url_for("get_all_posts"))
        else:
            flash("You've already signed up with that email, sign in instead!")
            return redirect("login")
    return render_template("register.html", form=form, current_user=current_user)


# TODO: Retrieve a user from the database based on their email.
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        find_user = db.session.execute(
            db.select(User).where(User.email == email)
        ).scalar()
        if find_user and check_password_hash(find_user.password, password):
            login_user(find_user)
            return redirect(url_for("get_all_posts"))
        else:
            flash("Email or password is incorrect! Try again!")
            return redirect("login")
    return render_template("login.html", form=form, current_user=current_user)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/")
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    form = CommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment")
            return redirect(url_for("login"))
        else:
            new_comment = Comment(
                text=form.comment.data, owner=current_user, blog=requested_post
            )
            db.session.add(new_comment)
            db.session.commit()
    return render_template(
        "post.html", post=requested_post, form=form, current_user=current_user
    )


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y"),
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body,
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template(
        "make-post.html", form=edit_form, is_edit=True, current_user=current_user
    )


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for("get_all_posts"))


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user)


if __name__ == "__main__":
    app.run(debug=True, port=5002)
