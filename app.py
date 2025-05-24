import os
from flask import Flask, render_template, redirect, url_for, request, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import qrcode
from io import BytesIO

# Create required directories and set absolute paths
base_dir = os.path.abspath(os.path.dirname(__file__))
instance_dir = os.path.join(base_dir, 'instance')
uploads_dir = os.path.join(base_dir, 'static', 'uploads')

def create_required_directories():
    for directory in [instance_dir, uploads_dir]:
        if not os.path.exists(directory):
            os.makedirs(directory)

# Create directories before initializing app
create_required_directories()

app = Flask(__name__)
app.config.update(
    SECRET_KEY='your_secret_key_here',
    SQLALCHEMY_DATABASE_URI=f'sqlite:///{os.path.join(instance_dir, "app.db")}',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    UPLOAD_FOLDER=uploads_dir,
    MAX_CONTENT_LENGTH=16 * 1024 * 1024  # 16MB max upload
)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)


class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)  # Lost or Found
    image = db.Column(db.String(150))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Routes

@app.route('/')
def home():
    return redirect(url_for('found_items'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email,
                        password_hash=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/post_item', methods=['GET', 'POST'])
@login_required
def post_item():
    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form['description'].strip()
        category = request.form['category']
        file = request.files.get('image')

        filename = None
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        item = Item(title=title, description=description,
                    category=category, image=filename, user_id=current_user.id)
        db.session.add(item)
        db.session.commit()
        flash('Item posted successfully.', 'success')
        return redirect(url_for('my_items'))

    return render_template('post_item.html')


@app.route('/my_items')
@login_required
def my_items():
    items = Item.query.filter_by(user_id=current_user.id).all()
    return render_template('my_items.html', items=items)


@app.route('/found_items')
@login_required
def found_items():
    items = Item.query.filter_by(category='Found').all()
    return render_template('found_items.html', items=items)


@app.route('/lost_items')
@login_required
def lost_items():
    items = Item.query.filter_by(category='Lost').all()
    return render_template('lost_items.html', items=items)


@app.route('/item_qr/<int:item_id>')
@login_required
def item_qr(item_id):
    item = Item.query.get_or_404(item_id)
    qr_data = f"Item: {item.title}\nDescription: {item.description}\nCategory: {item.category}"
    img = qrcode.make(qr_data)
    buf = BytesIO()
    img.save(buf)
    buf.seek(0)
    return send_file(buf, mimetype='image/png')


@app.route('/delete_item/<int:item_id>', methods=['POST'])
@login_required
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    
    # Check if user is authorized to delete (owner or admin)
    if item.user_id != current_user.id and not current_user.is_admin:
        flash('You are not authorized to delete this item.', 'danger')
        return redirect(url_for('found_items'))
    
    try:
        # Delete the image file if it exists
        if item.image:
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], item.image)
            if os.path.exists(image_path):
                os.remove(image_path)
        
        # Delete the database record
        db.session.delete(item)
        db.session.commit()
        flash('Item deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting item.', 'danger')
        
    return redirect(url_for('found_items'))


# Admin routes (minimal for demo)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('home'))

    total_users = User.query.count()
    total_items = Item.query.count()
    found_items = Item.query.filter_by(category='Found').count()
    lost_items = Item.query.filter_by(category='Lost').count()

    return render_template('admin/dashboard.html',
                           total_users=total_users,
                           total_items=total_items,
                           found_items=found_items,
                           lost_items=lost_items)


@app.route('/admin/listed_found')
@login_required
def admin_listed_found():
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('home'))
    items = Item.query.filter_by(category='Found').all()
    return render_template('admin/listed_found.html', items=items)


@app.route('/admin/claims')
@login_required
def admin_claims():
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('home'))
    return render_template('admin/claims.html')


@app.route('/admin/reports')
@login_required
def admin_reports():
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('home'))
    users = User.query.all()
    items = Item.query.all()
    return render_template('admin/reports.html', users=users, items=items)


@app.route('/admin/settings')
@login_required
def admin_settings():
    if not current_user.is_admin:
        flash('Access denied', 'danger')
        return redirect(url_for('home'))
    return render_template('admin/settings.html')


@app.cli.command('init-db')
def init_db_command():
    """Initialize the database."""
    with app.app_context():
        db.create_all()
        # Create admin user if not exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash('admin123'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin user created!")
    print('Initialized the database.')

if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
            print("Database created successfully!")
            
            # Create admin user if not exists
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                admin = User(
                    username='admin',
                    email='admin@example.com',
                    password_hash=generate_password_hash('admin123'),
                    is_admin=True
                )
                db.session.add(admin)
                db.session.commit()
                print("Admin user created!")
                
        except Exception as e:
            print(f"Error creating database: {e}")
            
    app.run(debug=True)
