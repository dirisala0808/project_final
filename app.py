import base64
import numpy as np
import io
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
from PIL import Image
import keras
from keras import backend as k
from keras.models import Sequential
from keras.models import load_model
from keras.preprocessing.image import ImageDataGenerator
from keras.preprocessing.image import img_to_array
from flask import Flask, Response, render_template, jsonify, request, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_login import UserMixin
from flask_login import login_user, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = '12345'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def get_model():
    global model
    model = load_model('C:\capstone_pneumonia_detection\project_final\PneumoniaDetection_model.h5')
    print("Model Loaded!")


def preprocess_image(image, target_size):
    if image.mode != "RGB":
        image = image.convert("RGB")
    image = image.resize(target_size)
    image = img_to_array(image)
    image = np.expand_dims(image, axis=0)

    return image



class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"
    
# with app.app_context():
#     db.create_all()

class Patients(db.Model):
    patient_id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(20), nullable=False)
    last_name = db.Column(db.String(20), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    gender = db.Column(db.String(20), nullable=False)
    symptoms = db.Column(db.String(120), nullable=False)
    normal_percentage = db.Column(db.Numeric(3), nullable=False)
    pneumonia_percentage = db.Column(db.Numeric(3), nullable=False)

    def __repr__(self):
        return f"Patients('{self.patient_id}','{self.first_name}', '{self.last_name}', '{self.symptoms}', '{self.normal_percentage}', '{self.pneumonia_percentage}')"

@app.route('/')
@app.route('/opening', methods=['GET'])
def opening():
    return render_template('opening.html')

@app.route('/')
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('usrnm')).first()
        if user:
            flash('That username is taken. Please choose a different one')
            return redirect('register')
        user1 = User.query.filter_by(email=request.form.get('email')).first()
        if user1:
            flash('That email is taken. Please choose a different one')
            return redirect('register')
        hashed_password = bcrypt.generate_password_hash(
            request.form.get('psw')).decode('utf-8')
        user = User(username=request.form.get('usrnm'),
                    email=request.form.get('email'), password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('You have Succesfully Registerd... Please Login...!!!')
        return redirect('login')
    return render_template('register.html')


@app.route('/homepage', methods=['GET', 'POST'])
def homapage():
    return render_template('homepage.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user and bcrypt.check_password_hash(user.password, request.form.get('psw')):
            login_user(user)
            return redirect('homepage')
        else:
            flash('Login Unsuccessful. Please check email and password')
            return redirect('login')
    return render_template('login.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect('login')


@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    return render_template('feedback.html')


@app.route('/aboutus')
def aboutus():
    return render_template('aboutus.html')


@app.route('/contact')
def contact():
    return render_template('contact.html')


@app.route('/predict_img', methods=['GET', 'POST'])
def predict_img():
    get_model()
    if request.method == 'POST':
        message = request.get_json(force=True)
        encoded = message['image']
        decoded = base64.b64decode(encoded)
        image = Image.open(io.BytesIO(decoded))
        processed_image = preprocess_image(image, target_size=(224, 224))
        prediction = model.predict(processed_image).tolist()
        normal_percentage = (prediction[0][0])*100
        pneumonia_percentage = (prediction[0][1])*100
        response = {
        'prediction': {
            'Normal': normal_percentage,
            'Pneumonia': pneumonia_percentage
            }
        }
        return jsonify(response)
    
    return render_template('predict_img.html')


@app.route('/get_details/<id>', methods=['GET'])
def show_details(id):
    results = Patients.query.filter_by(patient_id=id).first()
    if results == None:
        flash('No records found for that Patient ID')
    
    return render_template('show_details.html',results=results)

@app.route('/enter_details', methods=['GET','POST'])
def enter_details():
    if request.method == 'POST':
        pid = request.form.get('patientid')
        fname = request.form.get('firstname')
        lname = request.form.get('lastname')
        age = request.form.get('age')
        gender = request.form.get('gender')
        symptoms = request.form.get('subject')
        normal_percentage = request.form.get('normalpercent')
        pneumonia_percentage = request.form.get('pneumoniapercent')
        patient = Patients.query.filter_by(patient_id=pid).first()
        if patient:
            flash('Patient ID is already taken, Enter a correct ID')
        else:
            patient = Patients(patient_id=pid, first_name=fname, last_name=lname,
                                        age=age, gender=gender,symptoms=symptoms,normal_percentage=normal_percentage,pneumonia_percentage=pneumonia_percentage)
            db.session.add(patient)
            db.session.commit()
            return redirect(url_for('show_details', id=pid))
    return render_template('enter_details.html')

@app.route('/get_details' , methods=['GET','POST'])
def get_details():
    if request.method == 'POST':
        pid = request.form.get('search')
        return redirect(url_for('show_details', id=pid))
    return render_template('get_details.html')
'''
@app.route('/update_details', methods=['GET', 'POST'])
def update_details():
    if request.method == 'POST':
        pid = request.form.get('search')
        return redirect(url_for('update',id=pid))
    return render_template('update_details.html')

@app.route('/update_details/<id>', methods=['GET', 'POST'])
def update(id):
    result = Patients.query.get_or_404(id)
    if result == None:
        return "Record Not Found"
    if request.method == 'POST':
        result.first_name = request.form.get('firstname')
        result.last_name = request.form.get('lastname')
        result.patient_id = request.form.get('patientid')
        result.age = request.form.get('age')
        result.gender = request.form.get('gender')
        result.symptoms = request.form.get('subject')
        result.normal_percentage = request.form.get('normalpercent')
        result.pneumonia_percentage = request.form.get('pneumoniapercent')
        db.session.commit()
    elif request.method == 'GET':
        pid = request.form.get('patientid')
        fname = request.form.get('firstname')
        lname = request.form.get('lastname')
        age = request.form.get('age')
        gender = request.form.get('gender')
        symptoms = request.form.get('subject')
        normal_percentage = request.form.get('normalpercent')
        pneumonia_percentage = request.form.get('pneumoniapercent')
        fname = result.first_name
        lname = result.last_name
        pid = result.patient_id
        age = result.age
        gender = result.gender
        symptoms = result.symptoms
        normal_percentage = result.normal_percentage
        pneumonia_percentage = result.pneumonia_percentage
    return render_template('enter_details.html')
'''
@app.route('/inception_v3')
def inception_v3():
    return render_template('inception_v3.html')


@app.route('/vgg16')
def vgg16():
    return render_template('vgg16.html')


@app.route('/vgg19')
def vgg19():
    return render_template('vgg19.html')


if __name__ == '__main__':
    app.run(host='127.0.0.1', debug=True)

