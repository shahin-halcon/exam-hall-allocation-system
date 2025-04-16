# Exam Hall Allocation System

A Flask-based web application for managing exam hall allocations, student data, and exam schedules.

## Features

- Student management (add, view, edit student details)
- Hall management (add, view, edit hall details)
- Exam scheduling and allocation
- User authentication
- Dashboard for overview

## Prerequisites

- Python 3.8 or higher
- MySQL Server
- pip (Python package manager)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd exam-hall-allocation-system
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the project root with the following content:
```
SECRET_KEY=your-secret-key-here
DATABASE_URL=mysql://username:password@localhost/exam_hall_db
```

5. Create the MySQL database:
```sql
CREATE DATABASE exam_hall_db;
```

6. Initialize the database:
```bash
flask shell
>>> from app import app, db
>>> with app.app_context():
...     db.create_all()
```

## Running the Application

1. Start the Flask development server:
```bash
python app.py
```

2. Open your web browser and navigate to:
```
http://localhost:5000
```

## Usage

1. Login with your credentials
2. Navigate through the dashboard to:
   - Add/View/Edit students
   - Manage exam halls
   - Schedule exams
   - Allocate halls to exams

## Contributing

Feel free to submit issues and enhancement requests.

## License

This project is licensed under the MIT License. 