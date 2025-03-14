# imported libraries
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask_login import LoginManager, login_required, current_user
from flask_wtf import FlaskForm
from pdfkit import pdfkit
from wtforms import StringField, TextAreaField, DecimalField, IntegerField, FileField, SubmitField, PasswordField
from wtforms.validators import InputRequired, Length, DataRequired, ValidationError
from flask_wtf.file import FileAllowed
from werkzeug.utils import secure_filename, send_file
from flask_bcrypt import Bcrypt
from flask_login import UserMixin
from datetime import datetime
from flask_migrate import Migrate
from wtforms import DecimalField
from wtforms.widgets import NumberInput
from wtforms.widgets import Input
from flask import send_from_directory
from wtforms import widgets
from datetime import datetime
import os
import webbrowser
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user, logout_user
from uuid import uuid4

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = "SonOfFate"
app.config["UPLOAD_FOLDER"] = "static/images"

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
migrate = Migrate(app, db)

# Login page
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    cost_price = db.Column(db.Float, nullable=False)
    sale_price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    image = db.Column(db.String(100), nullable=False)

class Sale(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    buyer_name = db.Column(db.String(100), nullable=False)
    product_name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    sale_price = db.Column(db.Float, nullable=False)
    total_amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    cost_price = db.Column(db.Float, nullable=False)


# welcome page
@app.route('/')
def home():
    return render_template('home.html')

# register page
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder":"username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder":"password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(user=username.data).first()
        if existing_user_username:
            raise ValidationError("This username is taken. Please choose another username.")

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(user=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login"))
    return render_template('register.html', form=form)

# logout page
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

# login page
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "password"})
    submit = SubmitField('Login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(user=form.username.data).first()
        if user is None:
            flash("Invalid username or password", "error")
            return render_template('login.html', form=form)
        elif bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password", "error")
            return render_template('login.html', form=form)
    return render_template('login.html', form=form)

# dashboard page
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    products = Product.query.all()
    return render_template('dashboard.html', products=products, datetime=datetime)

class CurrencyInput(NumberInput):
    input_type = "number"

    def __call__(self, field, **kwargs):
        kwargs.setdefault("step", "0.01")
        kwargs.setdefault("min", "0")
        return super().__call__(field, **kwargs)

class ProductForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired()])
    cost_price = DecimalField('Cost Price (UGX)', validators=[DataRequired()], places=2)
    sale_price = DecimalField('Sale Price (UGX)', validators=[DataRequired()], places=2)
    quantity = IntegerField('Quantity', validators=[DataRequired()])
    image = FileField('Image', validators=[DataRequired()])
    submit = SubmitField('Add Product')

# add products page
@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    form = ProductForm()
    if form.validate_on_submit():
        name = form.name.data
        description = form.description.data
        cost_price = str(form.cost_price.data).replace(',', '')
        sale_price = str(form.sale_price.data).replace(',', '')
        quantity = form.quantity.data
        image = form.image.data

        cost_price_value = float(cost_price)
        sale_price_value = float(sale_price)

        filename = secure_filename(image.filename)
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        product = Product(
            name=name,
            description=description,
            cost_price=form.cost_price.data,
            sale_price=form.sale_price.data,
            quantity=quantity,
            image=filename
        )
        db.session.add(product)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('add_product.html', form=form)

# sales receipt
@app.route('/add_new_product', methods=['GET', 'POST'])
@login_required
def add_new_product():
    form = ProductForm()
    if form.validate_on_submit():
        name = form.name.data
        description = form.description.data
        cost_price = form.cost_price.data.replace(',', '')
        sale_price = form.sale_price.data.replace(',', '')
        quantity = form.quantity.data
        image = form.image.data

        cost_price_value = float(cost_price)
        sale_price_value = float(sale_price)

        filename = secure_filename(image.filename)
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        product = Product(
            name=name,
            description=description,
            cost_price=cost_price_value,
            sale_price=sale_price_value,
            quantity=quantity,
            image=filename
        )
        db.session.add(product)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('add_product.html', form=form)

# save receipt
@app.route('/sales_receipt_form', methods=['GET', 'POST'])
@login_required
def sales_receipt_form():
    products = Product.query.all()
    total = 0
    if request.method == 'POST':
        if request.form['action'] == 'generate_receipt':
            buyer_name = request.form['buyer_name']
            product_ids = request.form.getlist('product_name[]')
            quantities = request.form.getlist('quantity[]')
            sale_prices = request.form.getlist('sale_price[]')
            total_amounts = request.form.getlist('total_amount[]')

            product_names = [Product.query.get(int(product_id)).name for product_id in product_ids]

            receipt_data = {
                'buyer_name': buyer_name,
                'date': datetime.now(),
                'products': [
                    {
                        'product_name': product_names[i],
                        'quantity': quantities[i],
                        'sale_price': sale_prices[i],
                        'total_amount': total_amounts[i]
                    } for i in range(len(product_ids))
                ]
            }

            total_amount = 0
            for amount in total_amounts:
                if amount:
                    total_amount += float(amount)
            receipt_data['total_amount'] = total_amount

            if request.form['action'] == 'save_exit':
                # Save the receipt to the database
                sale = Sale(
                    buyer_name=receipt_data['buyer_name'],
                    date=receipt_data['date'],
                    total_amount=receipt_data['total_amount']
                )
                db.session.add(sale)
                db.session.commit()

                # Save the receipt products to the database
                for product in receipt_data['products']:
                    sale_product = SaleProduct(
                        sale_id=sale.id,
                        product_name=product['product_name'],
                        quantity=product['quantity'],
                        sale_price=product['sale_price'],
                        total_amount=product['total_amount']
                    )
                    db.session.add(sale_product)
                    db.session.commit()

                # Redirect back to the dashboard
                flash('Receipt saved successfully!', 'success')
                return redirect(url_for('dashboard'))
            
            if request.form['action'] == 'print_receipt':
                return render_template('print_receipt.html', receipt_data=receipt_data)

            return render_template('sales_receipt.html', receipt_data=receipt_data)
    return render_template('sales_receipt_form.html', products=products, total=total)

class EditProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired()])
    description = StringField('Product Description', validators=[DataRequired()])
    cost_price = DecimalField('Cost Price', validators=[DataRequired()])
    sale_price = DecimalField('Sale Price', validators=[DataRequired()])
    quantity = IntegerField('Quantity', validators=[DataRequired()])
    image = FileField('Product Image', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Update Product')


def save_image(image):
    # Generate a unique filename
    filename = secure_filename(image.filename)
    filename = str(uuid4()) + '.' + filename.split('.')[-1]

    # Save the image to the uploads folder
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    image.save(image_path)

    return filename

# edit product
@app.route('/edit_product/<int:id>', methods=['GET', 'POST'])
def edit_product(id):
    product = Product.query.get_or_404(id)
    form = EditProductForm(obj=product)
    if form.validate_on_submit():
        if form.image.data:
            image_path = save_image(form.image.data)
            product.image = image_path
        else:
            product.image = product.image  # Keep the existing image path
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('edit_product.html', form=form, product=product)

# search bar
@app.route('/search', methods=['POST'])
@login_required
def search():
    search_query = request.form['search_query']
    products = Product.query.filter(
        db.or_(
            Product.name.like(f'%{search_query}%'),
            Product.description.like(f'%{search_query}%')
        )
    ).all()
    return render_template('dashboard.html', products=products)

# view receipts
@app.route('/view_receipts')
def view_receipts():
    receipts_dir = './receipts'
    receipts = os.listdir(receipts_dir)
    return render_template('view_receipts.html', receipts=receipts)

@app.route('/view_receipt/<filename>')
def view_receipt(filename):
    receipts_dir = './receipts'
    return send_from_directory(receipts_dir, filename)

# receipt
@app.route('/receipt', methods=['GET', 'POST'])
def receipt():
    if request.method == 'POST':
        sale_price = float(request.form['sale_price'])
        quantity = int(request.form['quantity'])
        total_amount = sale_price * quantity
        return jsonify({'total_amount': total_amount})

    # Assuming you want to display a specific product's receipt
    product_id = 1  # Replace with the actual product ID
    product = Product.query.get(product_id)

    return render_template('sales_receipt.html', product=product)

@app.context_processor
def inject_now():
    return {'now': datetime.now()}

if __name__ == '__main__':
    app.run(debug=True)