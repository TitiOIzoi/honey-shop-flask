import os
from datetime import datetime, date, timedelta
from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from passlib.hash import pbkdf2_sha256
from werkzeug.utils import secure_filename
import uuid
import csv
from io import StringIO, BytesIO

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///honey.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-change-in-production')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(120))
    role = db.Column(db.String(20), default='customer')  # 'owner' or 'customer'

    def set_password(self, pw):
        self.password_hash = pbkdf2_sha256.hash(pw)

    def check_password(self, pw):
        return pbkdf2_sha256.verify(pw, self.password_hash)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    size = db.Column(db.String(20), nullable=False)  # '350g' or '500g'
    price_cents = db.Column(db.Integer, nullable=False)
    stock = db.Column(db.Integer, default=0)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # pending, paid, shipped, delivered
    total_cents = db.Column(db.Integer, default=0)
    customer_name = db.Column(db.String(120))
    customer_phone = db.Column(db.String(50))
    customer_address = db.Column(db.Text)

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    quantity = db.Column(db.Integer, default=1)
    unit_price_cents = db.Column(db.Integer, default=0)
    
    # Relationship to access product details
    product = db.relationship('Product', backref='order_items')

# --- Auth helpers ---
@login_manager.user_loader
def load_user(uid):
    return User.query.get(int(uid))

# --- DB init & seed ---
@app.before_first_request
def setup():
    db.create_all()
    # Seed products if empty - Updated pricing: 350g = RM35, 500g = RM60
    if Product.query.count() == 0:
        db.session.add_all([
            Product(name='Pure Natural Honey', size='350g', price_cents=3500, stock=100),
            Product(name='Pure Natural Honey', size='500g', price_cents=6000, stock=80)
        ])
        db.session.commit()
    # Seed admin if missing
    admin_email = os.getenv('ADMIN_EMAIL', 'admin@example.com')
    admin_pw = os.getenv('ADMIN_PASSWORD', 'admin123')
    admin = User.query.filter_by(email=admin_email).first()
    if not admin:
        admin = User(email=admin_email, name='Owner', role='owner')
        admin.set_password(admin_pw)
        db.session.add(admin)
        db.session.commit()

# --- Utility ---
def cart_items():
    return session.get('cart', [])

def cart_total_cents(items=None):
    items = items or cart_items()
    total = 0
    for it in items:
        total += it['price_cents'] * it['qty']
    return total

# --- Public routes ---
@app.route('/')
def index():
    products = Product.query.order_by(Product.size).all()
    return render_template('index.html', products=products)

@app.route('/add-to-cart', methods=['POST'])
def add_to_cart():
    product_id = int(request.form['product_id'])
    qty = int(request.form.get('qty', 1))
    product = Product.query.get_or_404(product_id)
    items = cart_items()
    # merge if same product
    for it in items:
        if it['product_id'] == product.id:
            it['qty'] += qty
            break
    else:
        items.append({
            'product_id': product.id,
            'name': f"{product.name} ({product.size})",
            'price_cents': product.price_cents,
            'qty': qty
        })
    session['cart'] = items
    flash('Added to cart', 'success')
    return redirect(url_for('index'))

@app.route('/cart')
def cart():
    return render_template('cart.html', items=cart_items(), total_cents=cart_total_cents())

@app.route('/update-cart', methods=['POST'])
def update_cart():
    items = cart_items()
    for i, it in enumerate(items):
        new_qty = int(request.form.get(f'qty_{i}', it['qty']))
        it['qty'] = max(0, new_qty)
    items = [it for it in items if it['qty'] > 0]
    session['cart'] = items
    flash('Cart updated', 'info')
    return redirect(url_for('cart'))

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    items = cart_items()
    if request.method == 'POST':
        if not items:
            flash('Your cart is empty', 'warning')
            return redirect(url_for('index'))
        name = request.form['name']
        phone = request.form['phone']
        address = request.form['address']
        order = Order(customer_name=name, customer_phone=phone, customer_address=address, status='paid')
        if current_user.is_authenticated:
            order.user_id = current_user.id
        db.session.add(order)
        db.session.flush()
        total = 0
        for it in items:
            product = Product.query.get(it['product_id'])
            if product.stock < it['qty']:
                flash(f'Not enough stock for {product.size}', 'danger')
                return redirect(url_for('cart'))
            product.stock -= it['qty']
            db.session.add(OrderItem(order_id=order.id, product_id=product.id, quantity=it['qty'], unit_price_cents=product.price_cents))
            total += product.price_cents * it['qty']
        order.total_cents = total
        db.session.commit()
        session['cart'] = []
        return redirect(url_for('receipt', order_id=order.id))
    return render_template('checkout.html', items=items, total_cents=cart_total_cents(items))

@app.route('/receipt/<int:order_id>')
def receipt(order_id):
    order = Order.query.get_or_404(order_id)
    items = OrderItem.query.filter_by(order_id=order.id).all()
    return render_template('receipt.html', order=order, items=items)

# --- Customer auth ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        pw = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(pw):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        pw = request.form['password']
        name = request.form['name']
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'warning')
            return redirect(url_for('register'))
        user = User(email=email, name=name)
        user.set_password(pw)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

# --- Admin ---
from functools import wraps

def owner_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'owner':
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return wrapper

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        pw = request.form['password']
        user = User.query.filter_by(email=email, role='owner').first()
        if user and user.check_password(pw):
            login_user(user)
            return redirect(url_for('admin_dashboard'))
        flash('Invalid admin credentials', 'danger')
    return render_template('admin/login.html')

@app.route('/admin')
@owner_required
def admin_dashboard():
    today = date.today()
    start = datetime(today.year, today.month, today.day)
    end = datetime(today.year, today.month, today.day, 23, 59, 59)
    sales_today_cents = db.session.query(db.func.coalesce(db.func.sum(Order.total_cents), 0)).filter(Order.created_at.between(start, end)).scalar()
    orders_today = Order.query.filter(Order.created_at.between(start, end)).count()
    month_start = datetime(today.year, today.month, 1)
    revenue_month_cents = db.session.query(db.func.coalesce(db.func.sum(Order.total_cents), 0)).filter(Order.created_at >= month_start).scalar()

    latest_orders = Order.query.order_by(Order.created_at.desc()).limit(10).all()
    stock = Product.query.order_by(Product.size).all()
    return render_template('admin/dashboard.html',
                           sales_today_cents=sales_today_cents,
                           orders_today=orders_today,
                           revenue_month_cents=revenue_month_cents,
                           latest_orders=latest_orders,
                           stock=stock)

@app.route('/admin/orders')
@owner_required
def admin_orders():
    q = Order.query.order_by(Order.created_at.desc())
    status = request.args.get('status')
    if status:
        q = q.filter_by(status=status)
    orders = q.all()
    return render_template('admin/orders.html', orders=orders)

@app.route('/admin/orders/<int:order_id>/status', methods=['POST'])
@owner_required
def update_order_status(order_id):
    order = Order.query.get_or_404(order_id)
    order.status = request.form['status']
    db.session.commit()
    flash('Order status updated', 'success')
    return redirect(url_for('admin_orders'))

@app.route('/admin/products', methods=['GET', 'POST'])
@owner_required
def admin_products():
    if request.method == 'POST':
        size = request.form['size']
        price = float(request.form['price'])
        stock = int(request.form['stock'])
        
        product = Product.query.filter_by(size=size).first()
        if product:
            product.price_cents = int(price * 100)
            product.stock = stock
        else:
            product = Product(
                name='Pure Natural Honey',
                size=size,
                price_cents=int(price * 100),
                stock=stock
            )
            db.session.add(product)
        
        db.session.commit()
        flash(f'Product {size} updated successfully', 'success')
        return redirect(url_for('admin_products'))
    
    products = Product.query.order_by(Product.size).all()
    return render_template('admin/products.html', products=products)

@app.route('/admin/export/orders')
@owner_required
def export_orders():
    """Export orders to CSV"""
    output = StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(['Order ID', 'Date', 'Customer', 'Phone', 'Product Size', 'Quantity', 'Unit Price', 'Total', 'Status'])
    
    # Data
    orders = db.session.query(Order, OrderItem, Product)\
        .join(OrderItem, Order.id == OrderItem.order_id)\
        .join(Product, OrderItem.product_id == Product.id)\
        .order_by(Order.created_at.desc()).all()
    
    for order, item, product in orders:
        writer.writerow([
            order.id,
            order.created_at.strftime('%Y-%m-%d %H:%M'),
            order.customer_name,
            order.customer_phone,
            product.size,
            item.quantity,
            f"RM {item.unit_price_cents / 100:.2f}",
            f"RM {order.total_cents / 100:.2f}",
            order.status.title()
        ])
    
    # Create response
    output.seek(0)
    
    # Convert to bytes for proper file download
    mem = BytesIO()
    mem.write(output.getvalue().encode('utf-8'))
    mem.seek(0)
    
    return send_file(
        mem,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'honey_orders_{datetime.now().strftime("%Y%m%d")}.csv'
    )

@app.route('/contact/whatsapp')
def whatsapp_contact():
    """Redirect to WhatsApp with pre-filled message"""
    phone = os.getenv('WHATSAPP_NUMBER', '+60123456789')  # Update this number
    message = "Hi! I'm interested in your Pure Natural Honey. Could you tell me more about your products?"
    
    whatsapp_url = f"https://wa.me/{phone.replace('+', '').replace(' ', '').replace('-', '')}?text={message}"
    return redirect(whatsapp_url)

# Template filters
@app.template_filter('currency')
def currency_filter(cents):
    """Convert cents to formatted currency"""
    return f"RM {cents / 100:.2f}"

@app.template_filter('status_class')
def status_class_filter(status):
    """Return Bootstrap class for order status"""
    status_classes = {
        'pending': 'warning',
        'paid': 'info',
        'shipped': 'primary',
        'delivered': 'success',
        'cancelled': 'danger'
    }
    return status_classes.get(status, 'secondary')

# Low stock check for admin
def check_low_stock():
    """Check for low stock products"""
    return Product.query.filter(Product.stock < 10).all()

@app.context_processor
def inject_low_stock():
    """Inject low stock alert into all admin templates"""
    if current_user.is_authenticated and current_user.role == 'owner':
        return {'low_stock_products': check_low_stock()}
    return {}

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
