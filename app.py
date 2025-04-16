from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from functools import wraps
from flask import session
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:bismi2003@localhost/exam_hall_allocation_new'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def student_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not isinstance(current_user, Student):
            flash('Please log in as a student to access this page.', 'error')
            return redirect(url_for('student_login'))
        return f(*args, **kwargs)
    return decorated_function

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, server_default='admin')

class Student(UserMixin, db.Model):
    __tablename__ = 'students'
    id = db.Column(db.Integer, primary_key=True)
    register_number = db.Column(db.String(20), unique=True, nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    course = db.Column(db.String(50), nullable=False)
    semester = db.Column(db.Integer, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default='Pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Hall(db.Model):
    __tablename__ = 'hall'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    building_name = db.Column(db.String(100), nullable=False)
    floor_number = db.Column(db.Integer, nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='Available')
    current_seat_number = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Exam(db.Model):
    __tablename__ = 'exam'
    id = db.Column(db.Integer, primary_key=True)
    course_name = db.Column(db.String(100), nullable=False)
    course_code = db.Column(db.String(10), nullable=False)
    exam_date = db.Column(db.DateTime, nullable=False)
    start_time = db.Column(db.Time, nullable=False)
    duration = db.Column(db.Integer, nullable=False)  # in minutes
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    # Add relationship to halls through allocations
    halls = db.relationship('Hall', secondary='exam_allocation', backref='exams')

class ExamAllocation(db.Model):
    __tablename__ = 'exam_allocation'
    id = db.Column(db.Integer, primary_key=True)
    exam_id = db.Column(db.Integer, db.ForeignKey('exam.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'), nullable=False)
    hall_id = db.Column(db.Integer, db.ForeignKey('hall.id'), nullable=True)
    seat_number = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    exam = db.relationship('Exam', backref='allocations')
    student = db.relationship('Student', backref='allocations')
    hall = db.relationship('Hall', backref='allocations')

class AdminNotification(db.Model):
    __tablename__ = 'admin_notification'
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(500), nullable=False)
    type = db.Column(db.String(20), default='info')  # info, warning, danger
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    # Check user type from session
    user_type = session.get('user_type')
    
    if user_type == 'admin':
        return User.query.get(int(user_id))
    elif user_type == 'student':
        return Student.query.get(int(user_id))
    return None

@app.route('/')
def index():
    # If user is already logged in, redirect to appropriate dashboard
    if current_user.is_authenticated:
        if isinstance(current_user, User) and current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif isinstance(current_user, Student):
            return redirect(url_for('student_dashboard'))
    # If not logged in, show the home page
    return render_template('index.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated and session.get('user_type') == 'admin':
        return redirect(url_for('admin_dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please provide both username and password', 'error')
            return render_template('admin_login.html')
            
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_type'] = 'admin'
            login_user(user)
            return redirect(url_for('admin_dashboard'))
                
        flash('Invalid username or password', 'error')
    return render_template('admin_login.html')

@app.route('/student/login', methods=['GET', 'POST'])
def student_login():
    if current_user.is_authenticated and session.get('user_type') == 'student':
        return redirect(url_for('student_dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please provide both username and password', 'error')
            return render_template('student_login.html')
            
        student = Student.query.filter(
            (Student.register_number == username) | 
            (Student.email == username)
        ).first()
        
        if student and student.check_password(password):
            session['user_type'] = 'student'
            login_user(student)
            return redirect(url_for('student_dashboard'))
                
        flash('Invalid registration number/email or password', 'error')
    return render_template('student_login.html')

@app.route('/login')
def login():
    # Redirect to home page since we now have separate login pages
    return redirect(url_for('index'))

@app.route('/student/register', methods=['GET', 'POST'])
def student_register():
    if request.method == 'POST':
        register_number = request.form.get('register_number')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        course = request.form.get('course')
        semester = request.form.get('semester')
        exam_id = request.form.get('exam_id')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Validate all required fields are present
        if not all([register_number, first_name, last_name, email, course, semester, exam_id, password, confirm_password]):
            flash('All fields are required')
            return redirect(url_for('student_register'))

        # Validate semester is a number between 1 and 8
        try:
            semester_num = int(semester)
            if semester_num < 1 or semester_num > 8:
                flash('Semester must be between 1 and 8')
                return redirect(url_for('student_register'))
        except (ValueError, TypeError):
            flash('Invalid semester value')
            return redirect(url_for('student_register'))

        if Student.query.filter_by(register_number=register_number).first():
            flash('Registration number already exists')
            return redirect(url_for('student_register'))

        if Student.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('student_register'))

        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('student_register'))

        # Verify exam exists
        exam = Exam.query.get(exam_id)
        if not exam:
            flash('Selected exam not found')
            return redirect(url_for('student_register'))

        try:
            # Create student
            student = Student(
                register_number=register_number,
                first_name=first_name,
                last_name=last_name,
                email=email,
                course=course,
                semester=semester_num,
                status='Pending'  # Initial status
            )
            student.set_password(password)
            db.session.add(student)
            db.session.flush()  # This assigns an ID to the student

            # Find available hall for the exam
            available_hall = Hall.query.filter(
                (Hall.status != 'Full')
            ).order_by(Hall.name).first()

            if available_hall:
                # Calculate next seat number
                next_seat_number = (available_hall.current_seat_number or 0) + 1
                
                if next_seat_number <= available_hall.capacity:
                    # Create allocation with hall
                    allocation = ExamAllocation(
                        exam_id=int(exam_id),
                        student_id=student.id,
                        hall_id=available_hall.id,
                        seat_number=str(next_seat_number)
                    )
                    
                    # Update hall's seat count
                    available_hall.current_seat_number = next_seat_number
                    if next_seat_number >= available_hall.capacity:
                        available_hall.status = 'Full'
                        # Create notification for admin
                        notification = AdminNotification(
                            message=f'Hall {available_hall.name} is now full for exam {exam.course_name}',
                            type='warning'
                        )
                        db.session.add(notification)
                    
                    student.status = 'Allocated'
                else:
                    # Create notification for admin about hall capacity
                    notification = AdminNotification(
                        message=f'Hall {available_hall.name} has reached capacity. New hall needed for exam {exam.course_name}',
                        type='warning'
                    )
                    db.session.add(notification)
                    # Create allocation without hall
                    allocation = ExamAllocation(
                        exam_id=int(exam_id),
                        student_id=student.id,
                        seat_number='TBA'
                    )
            else:
                # No available hall
                notification = AdminNotification(
                    message=f'No available halls for exam {exam.course_name}. Student {register_number} waiting for allocation.',
                    type='warning'
                )
                db.session.add(notification)
                # Create allocation without hall
                allocation = ExamAllocation(
                    exam_id=int(exam_id),
                    student_id=student.id,
                    seat_number='TBA'
                )
            
            db.session.add(allocation)
            db.session.commit()
            flash('Registration successful! Please login.')
            return redirect(url_for('student_login'))
        except Exception as e:
            db.session.rollback()
            flash('Error during registration')
            return redirect(url_for('student_register'))

    # GET request - show registration form
    exams = Exam.query.filter(
        Exam.exam_date >= datetime.now()  # Only show upcoming exams
    ).order_by(
        Exam.exam_date.asc(), 
        Exam.start_time.asc()
    ).all()
    
    return render_template('student/register.html', exams=exams)

@app.route('/student/profile')
@login_required
def student_profile():
    if not isinstance(current_user, Student):
        flash('Access denied')
        return redirect(url_for('index'))
    
    # Modified query to left join with Hall to include allocations without halls
    allocations = ExamAllocation.query.filter_by(student_id=current_user.id)\
        .join(Exam)\
        .outerjoin(Hall)\
        .order_by(Exam.exam_date, Exam.start_time)\
        .all()
    
    return render_template('student/profile.html', student=current_user, allocations=allocations)

@app.route('/student/hall-ticket')
@login_required
@student_required
def hall_ticket():
    student = Student.query.get(current_user.id)
    if not student:
        flash('Student record not found', 'error')
        return redirect(url_for('student_dashboard'))
        
    # Get the student's exam allocation with hall information
    allocation = ExamAllocation.query.filter_by(student_id=student.id)\
        .join(Exam)\
        .outerjoin(Hall)\
        .first()
    
    if not allocation:
        flash('No exam allocation found', 'error')
        return redirect(url_for('student_dashboard'))
        
    return render_template('student/hall_ticket.html', 
                         student=student, 
                         allocation=allocation,
                         exam=allocation.exam,
                         hall=allocation.hall)

def allocate_hall_for_student(student):
    exam = Exam.query.get(student.exam_id)
    if not exam:
        create_notification('Error: Exam not found for student allocation', 'danger')
        return False

    # Find available hall with capacity
    available_hall = Hall.query.filter_by(
        exam_id=exam.id
    ).filter(
        Hall.current_seat_number < Hall.capacity
    ).first()

    if not available_hall:
        # Try to find a new hall to allocate for this exam
        unallocated_hall = Hall.query.filter_by(exam_id=None, status='Available').first()
        if unallocated_hall:
            unallocated_hall.exam_id = exam.id
            available_hall = unallocated_hall
        else:
            create_notification(
                f'No available halls for exam {exam.course_name}. Student {student.register_number} could not be allocated.',
                'danger'
            )
            return False

    try:
        # Allocate the student to the hall
        available_hall.current_seat_number += 1
        student.hall_id = available_hall.id
        student.seat_number = available_hall.current_seat_number
        student.status = 'Allocated'

        # Create exam allocation record
        allocation = ExamAllocation(
            exam_id=exam.id,
            student_id=student.id,
            hall_id=available_hall.id,
            seat_number=available_hall.current_seat_number
        )
        db.session.add(allocation)

        # Check if hall is now full
        if available_hall.current_seat_number >= available_hall.capacity:
            available_hall.status = 'Full'
            create_notification(
                f'Hall {available_hall.name} is now full for exam {exam.course_name}',
                'warning'
            )

        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        create_notification(
            f'Error allocating seat for student {student.register_number}: {str(e)}',
            'danger'
        )
        return False

def create_notification(message, type='info'):
    notification = AdminNotification(message=message, type=type)
    db.session.add(notification)
    db.session.commit()

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not isinstance(current_user, User) or current_user.role != 'admin':
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin/notifications')
@login_required
@admin_required
def admin_notifications():
    notifications = AdminNotification.query.order_by(AdminNotification.created_at.desc()).all()
    return render_template('admin/notifications.html', notifications=notifications)

@app.route('/admin/notifications/mark-read/<int:id>', methods=['POST'])
@login_required
@admin_required
def mark_notification_read(id):
    notification = AdminNotification.query.get_or_404(id)
    notification.is_read = True
    db.session.commit()
    return jsonify({'success': True})

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    total_halls = Hall.query.count()
    total_students = Student.query.count()
    total_exams = Exam.query.count()
    # Count allocations that have no hall assigned yet
    pending_allocations = ExamAllocation.query.filter_by(hall_id=None).count()
    
    recent_notifications = AdminNotification.query.filter_by(is_read=False)\
        .order_by(AdminNotification.created_at.desc())\
        .limit(5).all()
        
    upcoming_exams = Exam.query.filter(Exam.exam_date >= datetime.now())\
        .order_by(Exam.exam_date.asc())\
        .limit(5).all()
        
    return render_template('admin/dashboard.html',
        total_halls=total_halls,
        total_students=total_students,
        total_exams=total_exams,
        pending_allocations=pending_allocations,
        notifications=recent_notifications,
        upcoming_exams=upcoming_exams
    )

@app.route('/student/dashboard')
@login_required
@student_required
def student_dashboard():
    student = Student.query.get(current_user.id)
    if not student:
        flash('Student record not found', 'error')
        return redirect(url_for('logout'))
        
    allocations = ExamAllocation.query.filter_by(student_id=current_user.id).all()
    return render_template('student/dashboard.html', allocations=allocations, student=student)

@app.route('/logout')
@login_required
def logout():
    session.pop('user_type', None)
    logout_user()
    return redirect(url_for('index'))

@app.route('/halls')
@login_required
def halls():
    halls = Hall.query.order_by(Hall.created_at.desc()).all()
    return render_template('halls.html', halls=halls)

@app.route('/halls/add', methods=['POST'])
@login_required
def add_hall():
    name = request.form.get('name')
    building_name = request.form.get('building_name')
    floor_number = request.form.get('floor_number')
    capacity = request.form.get('capacity')
    status = request.form.get('status', 'Available')
    
    if not all([name, building_name, floor_number, capacity]):
        flash('All fields are required', 'error')
        return redirect(url_for('halls'))
    
    new_hall = Hall(
        name=name,
        building_name=building_name,
        floor_number=int(floor_number),
        capacity=int(capacity),
        status=status
    )
    
    try:
        db.session.add(new_hall)
        db.session.commit()
        flash('Hall added successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error adding hall', 'error')
    
    return redirect(url_for('halls'))

@app.route('/halls/<int:id>/delete', methods=['POST'])
@login_required
def delete_hall(id):
    hall = Hall.query.get_or_404(id)
    try:
        db.session.delete(hall)
        db.session.commit()
        flash('Hall deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting hall', 'error')
    
    return redirect(url_for('halls'))

@app.route('/halls/<int:id>/update', methods=['POST'])
@login_required
def update_hall(id):
    if not hasattr(current_user, 'role') or current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    hall = Hall.query.get_or_404(id)
    name = request.form.get('name')
    building_name = request.form.get('building_name')
    floor_number = request.form.get('floor_number')
    capacity = request.form.get('capacity')
    status = request.form.get('status')
    
    if not all([name, building_name, floor_number, capacity]):
        flash('All fields are required', 'error')
        return redirect(url_for('halls'))
    
    try:
        # Check if reducing capacity is possible
        new_capacity = int(capacity)
        if new_capacity < hall.current_seat_number:
            flash('Cannot reduce capacity below current seat number', 'error')
            return redirect(url_for('halls'))
        
        hall.name = name
        hall.building_name = building_name
        hall.floor_number = int(floor_number)
        hall.capacity = new_capacity
        hall.status = status
        
        db.session.commit()
        flash('Hall updated successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error updating hall', 'error')
    
    return redirect(url_for('halls'))

@app.route('/exams')
@login_required
def exams():
    exams = Exam.query.order_by(Exam.exam_date.desc()).all()
    return render_template('exams.html', exams=exams)

@app.route('/admin/exams/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_exam():
    if request.method == 'POST':
        try:
            course_name = request.form.get('course_name')
            exam_date = request.form.get('exam_date')
            start_time = request.form.get('start_time')
            duration = request.form.get('duration')
            course_code = request.form.get('course_code')

            if not all([course_name, exam_date, start_time, duration, course_code]):
                flash('All fields are required', 'error')
                return redirect(url_for('exams'))

            # Convert date and time strings to Python objects
            exam_date_obj = datetime.strptime(exam_date, '%Y-%m-%d')
            start_time_obj = datetime.strptime(start_time, '%H:%M').time()

            # Create new exam
            exam = Exam(
                course_name=course_name,
                course_code=course_code,
                exam_date=exam_date_obj,
                start_time=start_time_obj,
                duration=int(duration)
            )

            db.session.add(exam)
            db.session.commit()
            flash('Exam added successfully', 'success')
            return redirect(url_for('exams'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding exam: {str(e)}', 'error')
            return redirect(url_for('exams'))

    return render_template('admin/add_exam.html')

@app.route('/exams/<int:exam_id>/delete', methods=['POST'])
@login_required
def delete_exam(exam_id):
    if not hasattr(current_user, 'role') or current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    exam = Exam.query.get_or_404(exam_id)
    try:
        # First delete all allocations for this exam
        ExamAllocation.query.filter_by(exam_id=exam_id).delete()
        
        # Then delete the exam
        db.session.delete(exam)
        db.session.commit()
        flash('Exam deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting exam', 'error')
    
    return redirect(url_for('exams'))

@app.route('/exams/<int:exam_id>')
@login_required
def exam_details(exam_id):
    exam = Exam.query.get_or_404(exam_id)
    return render_template('exam_details.html', exam=exam)

@app.route('/allocations')
@login_required
def allocations():
    if not hasattr(current_user, 'role') or current_user.role != 'admin':
        flash('Access denied')
        return redirect(url_for('index'))
    
    # Get all allocations with related data using outer join for halls
    allocations = db.session.query(
        ExamAllocation,
        Student,
        Exam,
        Hall
    ).join(
        Student, ExamAllocation.student_id == Student.id
    ).join(
        Exam, ExamAllocation.exam_id == Exam.id
    ).outerjoin(  # Changed to outerjoin for halls
        Hall, ExamAllocation.hall_id == Hall.id
    ).all()
    
    # Get available halls (not full)
    available_halls = Hall.query.filter(
        Hall.status != 'Full'
    ).order_by(Hall.name).all()
    
    return render_template('allocations.html', 
                         allocations=allocations,
                         exams=Exam.query.all(),
                         halls=available_halls,  # Only show available halls
                         students=Student.query.all())

@app.route('/allocations/add', methods=['POST'])
@login_required
def add_allocation():
    if not hasattr(current_user, 'role') or current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403
    
    exam_id = request.form.get('exam_id')
    student_id = request.form.get('student_id')
    hall_id = request.form.get('hall_id')
    
    if not all([exam_id, student_id, hall_id]):
        flash('All fields are required')
        return redirect(url_for('allocations'))
    
    try:
        # Get the hall and check its capacity
        hall = Hall.query.get(hall_id)
        if not hall:
            flash('Selected hall not found')
            return redirect(url_for('allocations'))
        
        # Check if student already has an allocation for this exam
        existing_allocation = ExamAllocation.query.filter_by(
            exam_id=exam_id,
            student_id=student_id
        ).first()
        
        if existing_allocation:
            if existing_allocation.hall_id is None:
                # Update existing allocation with hall information
                next_seat_number = (hall.current_seat_number or 0) + 1
                
                existing_allocation.hall_id = hall_id
                existing_allocation.seat_number = str(next_seat_number)
                
                # Update hall's current seat count
                hall.current_seat_number = next_seat_number
                
                # Update hall status if it becomes full
                if hall.current_seat_number >= hall.capacity:
                    hall.status = 'Full'
                
                # Update student status
                student = Student.query.get(student_id)
                if student:
                    student.status = 'Allocated'
                
                db.session.commit()
                flash('Hall assigned successfully')
            else:
                flash('Student already has a hall assigned for this exam')
            return redirect(url_for('allocations'))
        
        # Get the next available seat number
        next_seat_number = (hall.current_seat_number or 0) + 1
        
        if next_seat_number > hall.capacity:
            flash('Selected hall is full')
            return redirect(url_for('allocations'))
        
        # Create new allocation
        allocation = ExamAllocation(
            exam_id=int(exam_id),
            student_id=int(student_id),
            hall_id=int(hall_id),
            seat_number=str(next_seat_number)
        )
        
        # Update hall's current seat count
        hall.current_seat_number = next_seat_number
        
        # Update hall status if it becomes full
        if hall.current_seat_number >= hall.capacity:
            hall.status = 'Full'
        
        # Update student status
        student = Student.query.get(student_id)
        if student:
            student.status = 'Allocated'
        
        db.session.add(allocation)
        db.session.commit()
        flash('Allocation added successfully')
    except Exception as e:
        db.session.rollback()
        flash(f'Error adding allocation: {str(e)}')
    
    return redirect(url_for('allocations'))

@app.route('/students')
@login_required
def students():
    if not hasattr(current_user, 'role') or current_user.role != 'admin':
        flash('Access denied')
        return redirect(url_for('index'))
    
    students = Student.query.order_by(Student.created_at.desc()).all()
    return render_template('students.html', students=students)

@app.route('/students/<int:student_id>/edit', methods=['GET'])
@login_required
def edit_student(student_id):
    if not hasattr(current_user, 'role') or current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    student = Student.query.get_or_404(student_id)
    exams = Exam.query.filter(
        Exam.exam_date >= datetime.now()
    ).order_by(
        Exam.exam_date.asc(),
        Exam.start_time.asc()
    ).all()
    
    return render_template('admin/edit_student.html', student=student, exams=exams)

@app.route('/students/<int:student_id>/update', methods=['POST'])
@login_required
def update_student(student_id):
    if not hasattr(current_user, 'role') or current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    student = Student.query.get_or_404(student_id)
    try:
        # Update basic student information
        student.first_name = request.form.get('first_name')
        student.last_name = request.form.get('last_name')
        student.email = request.form.get('email')
        student.course = request.form.get('course')
        student.semester = int(request.form.get('semester'))
        student.status = request.form.get('status')
        
        # Handle password update if provided
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if password:
            if password != confirm_password:
                flash('Passwords do not match', 'error')
                return redirect(url_for('edit_student', student_id=student_id))
            student.set_password(password)
        
        # Handle exam allocation update if exam_id is provided
        exam_id = request.form.get('exam_id')
        if exam_id:
            # Check if student already has an allocation
            existing_allocation = ExamAllocation.query.filter_by(
                student_id=student.id
            ).first()
            
            if existing_allocation:
                # Update existing allocation
                if existing_allocation.exam_id != int(exam_id):
                    existing_allocation.exam_id = int(exam_id)
                    existing_allocation.hall_id = None
                    existing_allocation.seat_number = 'TBA'
                    student.status = 'Pending'
            else:
                # Create new allocation
                allocation = ExamAllocation(
                    exam_id=int(exam_id),
                    student_id=student.id,
                    seat_number='TBA'
                )
                db.session.add(allocation)
                student.status = 'Pending'
            
            # Try to find an available hall
            available_hall = Hall.query.filter(
                (Hall.status != 'Full')
            ).order_by(Hall.name).first()

            if available_hall and student.status != 'Allocated':
                next_seat_number = (available_hall.current_seat_number or 0) + 1
                if next_seat_number <= available_hall.capacity:
                    if existing_allocation:
                        existing_allocation.hall_id = available_hall.id
                        existing_allocation.seat_number = str(next_seat_number)
                    else:
                        allocation.hall_id = available_hall.id
                        allocation.seat_number = str(next_seat_number)
                    
                    available_hall.current_seat_number = next_seat_number
                    if next_seat_number >= available_hall.capacity:
                        available_hall.status = 'Full'
                    student.status = 'Allocated'
        
        db.session.commit()
        flash('Student information updated successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating student information: {str(e)}', 'error')
    
    return redirect(url_for('students'))

@app.route('/students/<int:student_id>/delete', methods=['POST'])
@login_required
def delete_student(student_id):
    if not hasattr(current_user, 'role') or current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    student = Student.query.get_or_404(student_id)
    try:
        # First delete all exam allocations for this student
        ExamAllocation.query.filter_by(student_id=student_id).delete()
        
        # Then delete the student
        db.session.delete(student)
        db.session.commit()
        flash('Student deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting student: {str(e)}', 'error')
    
    return redirect(url_for('students'))

@app.route('/exams/<int:exam_id>/edit', methods=['GET'])
@login_required
def edit_exam(exam_id):
    if not hasattr(current_user, 'role') or current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    exam = Exam.query.get_or_404(exam_id)
    return render_template('admin/edit_exam.html', exam=exam)

@app.route('/exams/<int:exam_id>/update', methods=['POST'])
@login_required
def update_exam(exam_id):
    if not hasattr(current_user, 'role') or current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    exam = Exam.query.get_or_404(exam_id)
    try:
        exam.course_name = request.form.get('course_name')
        exam.course_code = request.form.get('course_code')
        exam.exam_date = datetime.strptime(request.form.get('exam_date'), '%Y-%m-%d')
        exam.start_time = datetime.strptime(request.form.get('start_time'), '%H:%M').time()
        exam.duration = int(request.form.get('duration'))
        
        db.session.commit()
        flash('Exam updated successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error updating exam', 'error')
    
    return redirect(url_for('exams'))

@app.route('/allocations/<int:allocation_id>/edit', methods=['GET'])
@login_required
def edit_allocation(allocation_id):
    if not hasattr(current_user, 'role') or current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    allocation = ExamAllocation.query.get_or_404(allocation_id)
    exams = Exam.query.all()
    students = Student.query.all()
    halls = Hall.query.all()
    return render_template('admin/edit_allocation.html', 
                         allocation=allocation, 
                         exams=exams, 
                         students=students,
                         halls=halls)

@app.route('/allocations/<int:allocation_id>/update', methods=['POST'])
@login_required
def update_allocation(allocation_id):
    if not hasattr(current_user, 'role') or current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    allocation = ExamAllocation.query.get_or_404(allocation_id)
    try:
        # Get the old hall to update its seat count
        old_hall = Hall.query.get(allocation.hall_id)
        if old_hall:
            old_hall.current_seat_number = max(0, old_hall.current_seat_number - 1)
            if old_hall.current_seat_number < old_hall.capacity:
                old_hall.status = 'Available'

        # Update allocation
        allocation.exam_id = int(request.form.get('exam_id'))
        allocation.student_id = int(request.form.get('student_id'))
        allocation.hall_id = int(request.form.get('hall_id'))
        allocation.seat_number = request.form.get('seat_number')
        
        # Update student's hall information
        student = Student.query.get(allocation.student_id)
        if student:
            student.hall_id = allocation.hall_id
            student.seat_number = allocation.seat_number
            student.status = 'Allocated'

        # Update new hall's seat count
        new_hall = Hall.query.get(allocation.hall_id)
        if new_hall:
            new_hall.current_seat_number = new_hall.current_seat_number + 1
            if new_hall.current_seat_number >= new_hall.capacity:
                new_hall.status = 'Full'
        
        db.session.commit()
        flash('Allocation updated successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error updating allocation', 'error')
    
    return redirect(url_for('allocations'))

@app.route('/allocations/<int:allocation_id>/delete', methods=['POST'])
@login_required
def delete_allocation(allocation_id):
    if not hasattr(current_user, 'role') or current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('index'))
    
    allocation = ExamAllocation.query.get_or_404(allocation_id)
    try:
        db.session.delete(allocation)
        db.session.commit()
        flash('Allocation deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting allocation', 'error')
    
    return redirect(url_for('allocations'))

def create_admin_user():
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        admin_user = User(
            username='admin',
            password_hash=generate_password_hash('admin123'),
            role='admin'
        )
        try:
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created successfully!")
        except Exception as e:
            db.session.rollback()
            print("Error creating admin user:", str(e))

@app.route('/students/add', methods=['GET', 'POST'])
@login_required
def add_student():
    if not hasattr(current_user, 'role') or current_user.role != 'admin':
        flash('Access denied')
        return redirect(url_for('index'))

    if request.method == 'POST':
        register_number = request.form.get('register_number')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        course = request.form.get('course')
        semester = request.form.get('semester')
        exam_id = request.form.get('exam_id')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not all([register_number, first_name, last_name, email, course, semester, exam_id, password, confirm_password]):
            flash('All fields are required')
            return redirect(url_for('add_student'))

        if Student.query.filter_by(register_number=register_number).first():
            flash('Registration number already exists')
            return redirect(url_for('add_student'))

        if Student.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('add_student'))

        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('add_student'))

        try:
            # Create student
            student = Student(
                register_number=register_number,
                first_name=first_name,
                last_name=last_name,
                email=email,
                course=course,
                semester=semester,
                status='Pending'
            )
            student.set_password(password)
            db.session.add(student)
            db.session.flush()  # This assigns an ID to the student

            # Find available hall for the exam
            available_hall = Hall.query.filter(
                (Hall.status != 'Full')
            ).order_by(Hall.name).first()

            if available_hall:
                # Calculate next seat number
                next_seat_number = (available_hall.current_seat_number or 0) + 1
                
                if next_seat_number <= available_hall.capacity:
                    # Create allocation with hall
                    allocation = ExamAllocation(
                        exam_id=int(exam_id),
                        student_id=student.id,
                        hall_id=available_hall.id,
                        seat_number=str(next_seat_number)
                    )
                    
                    # Update hall's seat count
                    available_hall.current_seat_number = next_seat_number
                    if next_seat_number >= available_hall.capacity:
                        available_hall.status = 'Full'
                        # Create notification for admin
                        notification = AdminNotification(
                            message=f'Hall {available_hall.name} is now full',
                            type='warning'
                        )
                        db.session.add(notification)
                    
                    student.status = 'Allocated'
                else:
                    # Create notification for admin about hall capacity
                    notification = AdminNotification(
                        message=f'Hall {available_hall.name} has reached capacity. New hall needed.',
                        type='warning'
                    )
                    db.session.add(notification)
                    # Create allocation without hall
                    allocation = ExamAllocation(
                        exam_id=int(exam_id),
                        student_id=student.id,
                        seat_number='TBA'
                    )
            else:
                # No available hall
                notification = AdminNotification(
                    message=f'No available halls for new student {register_number}',
                    type='warning'
                )
                db.session.add(notification)
                # Create allocation without hall
                allocation = ExamAllocation(
                    exam_id=int(exam_id),
                    student_id=student.id,
                    seat_number='TBA'
                )
            
            db.session.add(allocation)
            db.session.commit()
            flash('Student added successfully')
            return redirect(url_for('students'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding student: {str(e)}')
            return redirect(url_for('add_student'))

    # GET request - show form
    exams = Exam.query.filter(
        Exam.exam_date >= datetime.now()
    ).order_by(
        Exam.exam_date.asc(),
        Exam.start_time.asc()
    ).all()
    
    return render_template('admin/add_student.html', exams=exams)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin_user()
    app.run(debug=True) 