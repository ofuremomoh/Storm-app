from flask import Flask, flash,  render_template, redirect, url_for, session, current_app, abort
from flask_sqlalchemy import SQLAlchemy 
#from flask_script import Manager
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, TextAreaField, HiddenField, SelectField
from flask_wtf.file import FileField, FileAllowed
import os
from base64 import b64encode
import base64
from io import BytesIO #Converts data from Database into bytes
from flask_migrate import Migrate
# Built-in Imports
import os
from datetime import datetime
from base64 import b64encode
import base64
from io import BytesIO #Converts data from Database into bytes
from flask_bootstrap import Bootstrap
from flask_login import UserMixin
import random

from random import randint
from flask_mail import Mail , Message
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager, login_required, logout_user, current_user, login_user, AnonymousUserMixin
import functools

# Flask
from flask import Flask, render_template, request, flash, redirect, url_for, send_file # Converst bytes into a file for downloads

# FLask SQLAlchemy, Database
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField,  TextAreaField, SelectField, FileField
from flask_wtf.file import FileField, FileAllowed, FileRequired, DataRequired
from sqlalchemy import create_engine


app = Flask(__name__)



#basedir = 'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'triple-s-systems.sqlite')


otp=randint(000000,999999)

#app.config['UPLOADED_PHOTOS_DEST'] = 'images'
#app.config['SQLALCHEMY_DATABASE_URI'] = basedir



#app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:CoreSocial94!@localhost:5433/rewind'

#app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://baiefmfbvcwctg:560383efc8de85f2216aac8bf95968e34ccd4f75c974f90cbac1e75f70e3b35f@ec2-52-4-104-184.compute-1.amazonaws.com:5432/degg0jb9ndgc1'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['DEBUG'] = True
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'info.starturn@gmail.com'
app.config['MAIL_PASSWORD'] = 'CoreSocial94!'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['SECRET_KEY'] = 'SECRET_KEY'
app.config['FLASKY_ADMIN'] = 'info.starturn@gmail.com, kelechi@triplessystems.ng'



db = SQLAlchemy(app)
migrate = Migrate(app, db)

mail = Mail(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

#configure_uploads(app, photos)



#manager = Manager(app)
#manager.add_command('db', MigrateCommand)

def render_picture(data):
    render_pic = base64.b64encode(data).decode('ascii') 
    return render_pic

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
    return user


def permission_required(permission):
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.can(permission):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    return permission_required(Permission.ADMIN)(f)



class User( UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(64))
    last_name = db.Column(db.String(64))
    email = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default=False)
    location = db.Column(db.String(64))
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(name='Administrator').first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()
  
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def can(self, perm):
        return self.role is not None and self.role.has_permission(perm)

    def is_administrator(self):
        return self.can(Permission.ADMIN)

class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False
        
    def is_administrator(self):
        return False

login_manager.anonymous_user = AnonymousUser


class Permission:
    ORDER = 1
    ADMIN = 2

class Role(db.Model):
    __tablename__ = 'role'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __init__(self, **kwargs):
        super(Role, self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions = 0

    def add_permission(self, perm):
        if not self.has_permission(perm):
            self.permissions += perm

    def remove_permission(self, perm):
        if self.has_permission(perm):
            self.permissions -= perm

    def reset_permissions(self):
        self.permissions = 0

    def has_permission(self, perm):
        return self.permissions & perm == perm

    @staticmethod
    def insert_roles():
        roles = {
            'User': [Permission.ORDER],

            'Administrator': [Permission.ORDER,
                              Permission.ADMIN]
        }

        default_role = 'User'
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.reset_permissions()
            for perm in roles[r]:
                role.add_permission(perm)
            role.default = (role.name == default_role)
            db.session.add(role)
        db.session.commit()


        
class Product(db.Model):
    __tablename__ = 'product'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True)
    price = db.Column(db.Integer) #in cents
    stock = db.Column(db.Integer)
    item_number = db.Column(db.Integer)
    description = db.Column(db.String(500))
    category = db.Column(db.String(100), unique=True)
    data = db.Column(db.Text, nullable=True)
    rendered_data = db.Column(db.Text, nullable=True)
    orders = db.relationship('Order_Item', backref= 'product', lazy=True)



class Order(db.Model):
     __tablename__ = 'order'

    id = db.Column(db.Integer, primary_key=True)
    reference = db.Column(db.String(5), unique=True)
    first_name = db.Column(db.String(20))
    last_name = db.Column(db.String(20))
    phone_number = db.Column(db.Integer)
    email = db.Column(db.String(20))
    address = db.Column(db.String(20))
    city = db.Column(db.String(20))
    state = db.Column(db.String(20))
    country = db.Column(db.String(20))
    status = db.Column(db.String(20))
    payment_type = db.Column(db.String(20))
    items = db.relationship('Order_Item', backref='order', lazy=True)

    def order_total(self):
        return db.session.query(db.func.sum(Order_Item.quantity * Product.price)).join(Product).filter(Order_Item.order_id == self.id).scalar()
      

class Order_Item(db.Model):
     __tablename__ = 'order_item'
     
     id = db.Column(db.Integer, primary_key=True)
     order_id = db.Column(db.Integer, db.ForeignKey('order.id'))
     product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
     quantity = db.Column(db.Integer)

     
class AddProduct(FlaskForm):
    name = StringField('Name')
    price = IntegerField('Price')
    stock = IntegerField('Stock')
    description = TextAreaField('Description')
    category = StringField('Category')
    image = FileField('Image')
    item_number = IntegerField('Item Number')
    
class AddToCart(FlaskForm):
    id = HiddenField('ID')
    quantity = IntegerField('Quantity')

class Checkout(FlaskForm):
     first_name = StringField('firstame')
     last_name = StringField('firstame')
     phone_number = IntegerField('firstame')
     email = StringField('Email')
     address = StringField('Address')
     city = StringField('City')
     state = StringField('Address')
     country =StringField('country')
     payment_type = StringField('Payment Type')


class RegistrationForm(FlaskForm):
    email = StringField('Email')
    first_name = StringField('FirstName')
    last_name = StringField('LastName')
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm password', validators=[DataRequired()])
    submit = SubmitField('Verify')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

class validationForm(FlaskForm):
	OTP  = IntegerField('Enter recived OTP')
	submit = SubmitField('Verify')

    
def handle_cart():
    products = []
    grand_total = 0
    index = 0 
    quantity_total = 0

    for item in session['cart']:
        product = Product.query.filter_by(id=item['id']).first()

        quantity = int(item['quantity'])
        total = quantity * product.price
        grand_total += total
        quantity_total += quantity

        products.append({'id' : product.id, 'name': product.name, 'price': product.price, 'rendered_data':product.rendered_data, 'quantity' : quantity, 'total': total, 'index': index })
        index += 1

    grand_total_plus_vat = grand_total + 1000

    return products, grand_total, grand_total_plus_vat, quantity_total


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('index')
            return redirect(next)
        flash('Invalid email or password.')
    return render_template('login.html', form=form)




@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('index'))

@app.route('/', methods=['GET', 'POST'])
def index(): 
    
    products = Product.query.all()

    
    return render_template('index.html', products=products ) 


#def handle_reg():
    #f



@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        #user = User(email=form.email.data.lower(),name=form.name.data,password=form.password.data)
        #db.session.add(user)
        #db.session.commit()
        #email = form.email.data
        password = form.password.data
        email=request.form['email']
        msg  = Message('Confirm Mail',sender='info.starturn@gmail.com',recipients=[email])
        msg.body='Your OTP is ' + str(otp)
        mail.send(msg)

        user = User(first_name=form.first_name.data, last_name=form.last_name.data, email=form.email.data.lower(),password=form.password.data)
        db.session.add(user)
        db.session.commit()


        return redirect(url_for('validate'))
    return render_template('register.html',form=form)

@app.route('/validate',methods=['GET','POST'])
def validate():
    form = validationForm()
    if form.validate_on_submit() and form.OTP.data == int(otp):
        current_user.confirm()
        db.session.commit()
        return '<h1> You have been verified! </h1>'
        
    return render_template ('check.html',form=form)


@app.route('/about')
def about(): 
    #products = Product.query.all()

    
    return render_template('about.html') #, products=products)


@app.route('/contact')
def contact(): 
    #products = Product.query.all()

    
    return render_template('contact.html') #, products=products)

@app.route('/admin-add', methods=['GET', 'POST'])
@admin_required
def add(): 
    form = AddProduct()

    if form.validate_on_submit():
        
        name = form.name.data
        price = form.price.data
        stock = form.stock.data
        description = form.description.data
        image = form.image.data
        category = form.category.data
        data= image.read()
        rendered_file = render_picture(data)

        new_product = Product(name=name, price=price, stock=stock, description=description, data=data, rendered_data=rendered_file)
        db.session.add(new_product)
        db.session.commit()
        return redirect(url_for('index'))

    return render_template('admin-add.html',form=form)

@app.route('/admin')
@admin_required
def admin(): 
    products = Product.query.all()
    products_in_stock = Product.query.filter(Product.stock > 0).count()

    orders = Order.query.all()

    return render_template('admin-dashboard.html', admin=True, products=products, products_in_stock=products_in_stock, orders=orders)

@app.route('/product-<id>')
def product(id): 
    product = Product.query.filter_by(id=id).first()

    form = AddToCart()

    return render_template('product.html', product=product, form=form)


@app.route('/cart')
def cart(): 
    products, grand_total, grand_total_plus_vat, quantity_total = handle_cart()  

    return render_template('cart.html', products=products, grand_total=grand_total, grand_total_plus_vat=grand_total_plus_vat)

@app.route('/quick-add-<id>')
def quick_add(id): 
    if 'cart' not in session: 
        session['cart'] = []
  

    session['cart'].append({'id': id, 'quantity': 1})
    session.modified = True

    return redirect(url_for('index'))
    
@app.route('/add-to-cart', methods=['GET','POST'])
def add_to_cart():
    if 'cart' not in session: 
        session['cart'] = []
    
    form = AddToCart()

    if form.validate_on_submit(): 
     
        session['cart'].append({'id': form.id.data, 'quantity' : form.quantity.data})
        session.modified = True

    return redirect(url_for('index'))

@app.route('/remove-from-cart-<index>')
def remove_from_cart(index):
    del session['cart'][int(index)]
    session.modified = True
    return redirect(url_for('cart')) 


@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    form = Checkout()
    products, grand_total, grand_total_plus_vat, quantity_total = handle_cart()

    if form.validate_on_submit():

        order = Order()
        form.populate_obj(order)
        order.reference = ''.join([random.choice('ABCDEFG') for _ in range(7)])
        order.status = 'PENDING'

        for product in products: 
            order_item = Order_Item(quantity=product['quantity'], product_id=product['id'])
            order.items.append(order_item)

            product = Product.query.filter_by(id=product['id']).update({'stock': Product.stock - product['quantity'] })

        db.session.add(order)
        db.session.commit()

        session['cart'] = []
        session.modified = True

        return redirect(url_for('index'))

    return render_template('checkout.html', form=form, products=products, grand_total=grand_total, grand_total_plus_vat=grand_total_plus_vat, quantity_total=quantity_total ) 

@app.route('/order-<order_id>')
@admin_required
def order(order_id):
    order = Order.query.filter_by(id=int(order_id)).first()
    return render_template('order.html', order=order, admin=True)  


if __name__ == '__main__':
    app.run()