
import os
from flask import Flask, render_template, request, url_for, session, redirect, jsonify, flash
from textblob import TextBlob
from bson import ObjectId
from nltk.tokenize import word_tokenize
from nltk.corpus import opinion_lexicon
from flask_pymongo import PyMongo
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from langchain_ollama import OllamaLLM
from langchain_core.prompts import ChatPromptTemplate
from datetime import datetime
from urllib.parse import quote_plus
import nltk

# Ensure necessary NLTK resources are downloaded
nltk.download('opinion_lexicon')

app = Flask(__name__)
app.config["SESSION_TYPE"] = "filesystem"

app.config["MONGO_URI"] = (
    "mongodb+srv://mohammedSayeedAdmin:S1a2y3e4e5d6@studentsphere.remkk.mongodb.net/studentsphere"
    "?retryWrites=true&w=majority&tls=true&tlsAllowInvalidCertificates=false"
)

# Add necessary MongoDB connection options
app.config["MONGO_CONNECT"] = False  # Prevent PyMongo from establishing connections on app initialization
app.config["MONGO_TLS"] = True       # Enable TLS for secure connections

# Initialize PyMongo
mongo = PyMongo(app)

# Test MongoDB connection
try:
    mongo.cx.admin.command("ping")
    print("MongoDB connection successful!")
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")

# Define the upload folder and allowed extensions
UPLOAD_FOLDER = 'static/uploads/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Secret key for session management
app.secret_key = 'your_secret_key'

# Function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

template = """
Answer the question below.

Here is the conversation history: {context}

Question: {question}

Answer:
"""
model = OllamaLLM(model="llama3")
prompt = ChatPromptTemplate.from_template(template)
chain = prompt | model


@app.route('/')
def dummy():
    # Redirect to '/your-page'
    print("MongoDB Object:", mongo)

    return render_template('login.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = False  # Initialize error flag

    if request.method == 'POST':
        # Print the received form data to debug the issue
        print("Form Data Received:", request.form)

        username = request.form.get('username')  # For student
        email = request.form.get('email')  # For admin
        password = request.form.get('password')
        login_type = request.form.get('login_type')

        # Ensure form fields are present
        if not password or not login_type or (login_type == 'student' and not username) or (login_type == 'admin' and not email):
            return "Bad Request: Missing form fields", 400

        # Debugging print statements
        print("Login type:", login_type)
        print("Username:", username if login_type == 'student' else email)  # Print relevant field
        print("Password:", password)

        try:
            if login_type == 'student':
                # Handle student login
                user = mongo.db.registered_users.find_one({"username": username})
                if user and check_password_hash(user['password'], password):
                    # Store user details in session
                    session['username'] = username
                    session['batch'] = user.get('batch', 'Unknown')
                    session['reg_number'] = user.get('reg_number', 'Unknown')

                    print("Student login successful")
                    hashed_password = generate_password_hash("admin123")
                    print(hashed_password)
                    return redirect('/home')
                else:
                    error = True
                    print("Invalid student login credentials")
            
            elif login_type == 'admin':
                # Handle admin login
                admin = mongo.db.admin_users.find_one({"email": email})  # Using email for admin login
                if admin and admin['password'] == password:
                    # Store admin details in session
                    session['admin_email'] = email

                    print("Admin login successful")
                    return redirect('/admindash')
                else:
                    error = True
                    print("Invalid admin login credentials")

        except Exception as err:
            print(f"Error: {err}")
            error = True

    return render_template('login.html', error=error)


@app.route('/home')
def index():
    username = session.get('username')
    user = mongo.db.registered_users.find_one({"username": username})
    profile_picture = user.get('profile_picture') if user else None
    feedbacks = list(mongo.db.feedbacks.find().sort("timestamp", -1))
    return render_template('index.html', username=username, profile_picture=profile_picture, feedbacks=feedbacks)


@app.route('/chat', methods=['POST'])
def chat():
    data = request.json
    user_input = data.get('message')
    context = data.get('context', "")  # Optional: Get conversation context if needed

    # Invoke the chatbot with user input
    result = chain.invoke({"context": context, "question": user_input})

    # Return the response as JSON
    return jsonify({"response": result})

@app.route('/explore')
def forum():
    return render_template('explore.html')


@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/project')
def project():
    return render_template('project.html')

@app.route('/quiz', methods=['GET', 'POST'])
def quiz():
    if request.method == 'POST':
        # Get quiz responses for all 10 questions
        answer1 = request.form.get('q1', '')
        answer2 = request.form.get('q2', '')
        answer3 = request.form.get('q3', '')
        answer4 = request.form.get('q4', '')
        answer5 = request.form.get('q5', '')
        answer6 = request.form.get('q6', '')
        answer7 = request.form.get('q7', '')
        answer8 = request.form.get('q8', '')
        answer9 = request.form.get('q9', '')
        answer10 = request.form.get('q10', '')

        # Get session data
        reg_number = session.get('reg_number', '')
        batch = session.get('batch', '')
        username = session.get('username', '')

        try:
            # Get the current time for createdAt
            created_at = datetime.utcnow()  # UTC timestamp

            # Prepare the data to be inserted into MongoDB
            quiz_data = {
                "createdAt": created_at,  # Add createdAt field
                "reg_number": reg_number,
                "batch": batch,
                "username": username,
                "answer1": answer1,
                "answer2": answer2,
                "answer3": answer3,
                "answer4": answer4,
                "answer5": answer5,
                "answer6": answer6,
                "answer7": answer7,
                "answer8": answer8,
                "answer9": answer9,
                "answer10": answer10,
            }

            # Insert data into MongoDB
            mongo.db.quiz_responses.insert_one(quiz_data)

            return redirect('/quiz')  # Or redirect to a confirmation page
        except Exception as e:
            return f'Error: {e}'

    return render_template('quiz.html')

@app.route('/contact', methods=['GET', 'POST'])  # Allow both GET and POST methods
def contact():
    if request.method == 'POST':
        # Retrieve username from session
        username = session.get('username')  # Assuming 'username' is saved in session after login

        if not username:
            return redirect(url_for('login'))  # Redirect to login if no username in session

        feedback_text = request.form.get('feedback')

        # Save feedback in MongoDB with timestamp and initial likes = 0
        feedback_data = {
            'username': username,  # Get the username from session
            'feedback': feedback_text,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),  # Timestamp
            'likes': 0  # Initial number of likes
        }

        mongo.db.feedbacks.insert_one(feedback_data)
        return redirect(url_for('index'))  # Redirect to the homepage after feedback submission

    return render_template('contact.html')  # Show the feedback form


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            # Retrieve form data
            username = request.form['username']
            email = request.form['email']
            reg_number = request.form['reg_number']
            password = request.form['password']
            batch = request.form['batch']
            profile_picture = request.files.get('profile_picture')

            # Check if 'registered_users' collection exists
            if 'registered_users' not in mongo.db.list_collection_names():
                mongo.db.create_collection('registered_users')

            # Check if the username already exists in the 'registered_users' collection
            existing_user = mongo.db.registered_users.find_one({"username": username})
            if existing_user:
                flash('Username already in use. Please choose a different one.', 'danger')
                return redirect('/register')

            # Handle profile picture upload
            profile_picture_path = None
            if profile_picture and allowed_file(profile_picture.filename):
                filename = secure_filename(profile_picture.filename)
                profile_picture_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                profile_picture.save(profile_picture_path)
                # Store relative path in MongoDB
                profile_picture_path = os.path.join('uploads', filename)

            # Create user document
            user_document = {
                "username": username,
                "email": email,
                "reg_number": reg_number,
                "password": generate_password_hash(password),  # Hash the password
                "batch": batch,
                "profile_picture": profile_picture_path  # Save path or filename
            }

            # Insert user document into 'registered_users' collection
            mongo.db.registered_users.insert_one(user_document)

            # Set session variable for the registered user
            session['reg_number'] = reg_number

            flash('Registration successful! Please log in.', 'success')
            return redirect('/login')

        except Exception as e:
            print(f'Error: {e}')
            return f'Error: {e}', 500

    return render_template('register.html')



@app.route('/admindash')
def admin_dash():
    if 'admin_email' in session:
        # Retrieve the analysis results from MongoDB and convert it to a list
        analysis_results = list(mongo.db.sentiment_analysis.find())

        # Count the registered users
        registered_users_count = mongo.db.registered_users.count_documents({})
        print(f"Registered users count: {registered_users_count}")  # Debug print
        
        # Count total positive sentiments
        total_positive_count = mongo.db.sentiment_analysis.count_documents({"sentiment": "Positive"})
        
        return render_template('admindash.html', 
                               analysis_list=analysis_results,  
                               registered_users_count=registered_users_count,  
                               total_positive_count=total_positive_count)  
    else:
        return redirect('/login')


@app.route('/quizdash', methods=['GET'])
def quiz_dash():
    # Fetch quiz responses from MongoDB and sort by 'createdAt' in descending order
    quiz_responses = mongo.db.quiz_responses.find().sort('createdAt', -1)  # -1 for descending order

    # Count total positive sentiments
    total_positive_count = mongo.db.sentiment_analysis.count_documents({"sentiment": "Positive"})

     # Count the registered users
    registered_users_count = mongo.db.registered_users.count_documents({})
    print(f"Registered users count: {registered_users_count}")  # Debug print

    return render_template('quizdash.html', quiz_responses=quiz_responses, total_positive_count=total_positive_count,
     registered_users_count=registered_users_count)
    


@app.route('/analyze', methods=['POST'])
def analyze():
    # Retrieve text input from the form
    text = request.form['text']

    # Retrieve user details from session
    username = session.get('username')
    reg_number = session.get('reg_number')
    batch = session.get('batch')


    #Initialize TextBlob for sentiment analysis
    blob = TextBlob(text)

    # Get the sentiment score
    sentiment_score = blob.sentiment.polarity

    # Determine the sentiment label based on the sentiment score
    sentiment = 'Positive' if sentiment_score > 0 else 'Negative'

    # Use NLTK's opinion lexicon to count positive and negative words in the input text
    positive_lexicon = set(opinion_lexicon.positive())
    negative_lexicon = set(opinion_lexicon.negative())
    tokens = word_tokenize(text.lower())  # Tokenize the text
    positive_count = sum(1 for token in tokens if token in positive_lexicon)
    negative_count = sum(1 for token in tokens if token in negative_lexicon)

    # Calculate the total number of words
    total_words = len(tokens)

    # Calculate the percentage of positive and negative words
    positive_percentage = (positive_count / total_words) * 100 if total_words > 0 else 0
    negative_percentage = (negative_count / total_words) * 100 if total_words > 0 else 0

    # Count stressful and depressive words
    stressful_words = ['stressed', 'stressing', 'stress', 'anxious', 'anxiety', 'anxiously', 'overwhelmed', 'overwhelming', 'tense', 'tension', 'tensely', 'panicked', 'panic', 'panicking', 'worried', 'worry', 'worrying', 'worryingly', 'nervous', 'nervously', 'nervousness', 'pressured', 'pressure', 'pressuring', 'burdened', 'burden', 'burdening', 'strained', 'strain', 'straining', 'exhausted', 'exhaustion', 'exhaustingly', 'fatigued', 'fatigue', 'fatiguing', 'frazzled', 'frazzling', 'overloaded', 'overloading', 'agitated', 'agitation', 'agitating', 'frantic', 'frantically', 'franticness', 'hectic', 'hecticness', 'jittery', 'jitteriness', 'jittering', 'struggling', 'struggle', 'struggled', 'on edge', 'edginess', 'overworked', 'overworking', 'rattled', 'rattling', 'drained', 'draining', 'overwrought', 'overwroughtness', 'under pressure', 'pressure', 'pressurized', 'stretched thin', 'thinly stretched', 'tired', 'tiredness', 'tiring', 'worn out', 'wearing out', 'anxiously', 'anxiousness', 'weary', 'weariness', 'run-down', 'running down', 'overburdened', 'overburdening', 'stretched', 'stretching', 'frustrated', 'frustration', 'frustrating', 'stressed out', 'stressing out', 'harried', 'harassing', 'stressed to the max', 'maximum stress', 'frenzied', 'frenzy', 'frenziedly', 'burned out', 'burnout', 'burning out', 'distracted', 'distracting', 'distractingly', 'fidgety', 'fidgeting', 'restless', 'restlessness', 'restlessly', 'overwrought', 'overwroughtness', 'on the brink', 'brink of stress', 'uneasy', 'uneasiness', 'uneasily', 'edgy', 'edginess', 'edgily', 'pressed for time', 'time pressure', 'under strain', 'strained', 'strain on', 'feeling the heat', 'heated', 'heating up']
    depressive_words = ['despair', 'despairing','depressed', 'despaired', 'grief', 'grieving', 'grieved', 'anguish', 'anguished', 'anguishing', 'melancholy', 'melancholic', 'melancholia', 'desolation', 'desolate', 'desolated', 'desolating', 'despairing', 'despaired', 'despair', 'despairing', 'desperate', 'desperation', 'desperately', 'disconsolate', 'disconsolately', 'forlorn', 'forlornness', 'heartbroken', 'heartbreak', 'heavyhearted', 'heavyheartedly', 'hopelessness', 'hopeless', 'lament', 'lamented', 'lamenting', 'melancholic', 'melancholia', 'mournful', 'mournfully', 'mournfulness', 'pain', 'painful', 'painfully', 'regret', 'regretful', 'regretfully', 'tearful', 'tears', 'tragic', 'tragically', 'tragedy', 'woeful', 'woefully', 'abandoned', 'abandonment', 'alienated', 'alienation', 'bereaved', 'bereavement', 'cheerless', 'cheerlessness', 'crushed', 'crushing', 'defeated', 'defeat', 'desperate', 'desperately', 'desperation', 'disappointed', 'disappointment', 'disheartened', 'disheartenment', 'distressed', 'distress', 'distressing', 'downcast', 'downhearted', 'downheartedly', 'downheartedness', 'gloomy', 'gloom', 'gloominess', 'grief-stricken', 'grief-strickenly', 'helpless', 'helplessness', 'hopeless', 'hopelessly', 'hopelessness', 'hurt', 'hurtful', 'hurtfully', 'hurtfulness', 'isolated', 'isolation', 'loneliness', 'lonely', 'lost', 'loss', 'miserable', 'miserably', 'misery', 'mourning', 'mourn', 'pathetic', 'pathetically', 'pessimistic', 'pessimism', 'powerless', 'powerlessness', 'rejected', 'rejection', 'sadness', 'sad', 'sorrow', 'sorrowful', 'sorrowfully', 'suffer', 'suffering', 'sufferingly', 'suffered', 'unhappy', 'unhappiness', 'unloved', 'unwanted', 'wretched', 'wretchedness', 'agonized', 'agonizing', 'agonizingly', 'anguished', 'anguishing', 'anguishingly', 'broken', 'brokenhearted', 'bitter', 'bitterness', 'dejected', 'dejection', 'deprived', 'deprivation', 'discontented', 'discontentment', 'downtrodden', 'dismayed', 'dismay', 'disillusioned', 'disillusionment', 'forlorn', 'forlornness', 'grieved', 'grieving', 'grievance', 'grievously', 'haunted', 'haunting', 'hopelessness', 'humiliated', 'humiliation', 'inconsolable', 'inconsolably', 'joyless', 'joylessness', 'longing', 'longingly', 'mournful', 'mournfully', 'mournfulness', 'nostalgic', 'nostalgia', 'nostalgically', 'numb', 'numbness', 'oppressed', 'oppression', 'regretful', 'regretfully', 'regretfulness', 'remorseful', 'remorsefully', 'remorsefulness', 'resentful', 'resentfully', 'resentfulness', 'shameful', 'shamefully', 'shamefulness', 'sorrowful', 'sorrowfully', 'sorrowfulness', 'suffering', 'sufferingly', 'suffered', 'tormented', 'torment', 'unappreciated', 'unappreciation', 'unfulfilled', 'unfulfillment', 'vulnerable', 'vulnerability', 'worthless', 'worthlessness', 'yearning', 'yearn', 'yearningly', 'alienation', 'alienated', 'alienating', 'betrayed', 'betrayal', 'condemned', 'condemnation', 'defeated', 'defeatism', 'defeatedly', 'deserted', 'desertion', 'desolate', 'desolately', 'desolation', 'disappointed', 'disappointingly', 'disappointment', 'embarrassed', 'embarrassment', 'excluded', 'exclusion', 'frustrated', 'frustration', 'gloomy', 'gloomily', 'gloominess', 'hollow', 'hollowness', 'humiliated', 'humiliation', 'inadequate', 'inadequacy', 'indifferent', 'indifference', 'insecure', 'insecurity', 'insignificant', 'insignificance', 'invalidated', 'invalidation', 'isolated', 'isolation', 'lonely', 'loneliness', 'lost', 'loss', 'meaningless', 'meaninglessness', 'neglected', 'neglect', 'numb', 'numbness', 'rejected', 'rejection', 'remorseful', 'remorsefulness', 'shameful', 'shamefully', 'shamefulness', 'trapped', 'entrapment', 'unwanted', 'unwantedness', 'useless', 'uselessness', 'victimized', 'victimization', 'weak', 'weakness', 'worthless', 'worthlessness', 'wounded', 'wound']
    stressful_count = sum(1 for token in tokens if token in stressful_words)
    depressive_count = sum(1 for token in tokens if token in depressive_words)

    # Therapist advice based on counts
    if positive_count > stressful_count:
        therapist_advice = "You are doing good. Enjoy your day!"
    elif stressful_count > positive_count:
        therapist_advice = "Do some Yoga and meditation."
    else:
        therapist_advice = "Please consider visiting a therapist."

    # Create a dictionary to hold the results
    analysis_result = {
        'username': username,
        'reg_number': reg_number,
        'batch': batch,
        'text': text,
        'sentiment': sentiment,
        'positive_count': positive_count,
        'negative_count': negative_count,
        'positive_percentage': positive_percentage,
        'negative_percentage': negative_percentage,
        'stressful_count': stressful_count,
        'depressive_count': depressive_count,
        'therapist_advice': therapist_advice
    }

    # Insert the analysis result into MongoDB
    mongo.db.sentiment_analysis.insert_one(analysis_result)

    # Pass the analysis results back to the project.html template
    return render_template('project.html', 
                           text=text, 
                           sentiment=sentiment,
                           positive_percentage=positive_percentage,
                           negative_percentage=negative_percentage,
                           positive_count=positive_count,
                           stressful_count=stressful_count,
                           depressive_count=depressive_count,
                           therapist_advice=therapist_advice)
@app.route('/like_feedback', methods=['POST'])
def like_feedback():
    if 'username' in session:  # Assuming user is logged in
        username = session['username']  # Get logged-in user
        feedback_id = request.form.get('feedback_id')  # Get feedback ID from request
        feedback = mongo.db.feedbacks.find_one({'_id': ObjectId(feedback_id)})

        if feedback:
            if username in feedback.get('liked_by', []):
                # User has already liked this feedback, so remove like
                mongo.db.feedbacks.update_one(
                    {'_id': ObjectId(feedback_id)},
                    {'$pull': {'liked_by': username}, '$inc': {'likes': -1}}
                )
                return {'status': 'unliked', 'likes': feedback['likes'] - 1}
            elif feedback['username'] != username:
                # User can like if they haven't already liked and it's not their feedback
                mongo.db.feedbacks.update_one(
                    {'_id': ObjectId(feedback_id)},
                    {'$addToSet': {'liked_by': username}, '$inc': {'likes': 1}}
                )
                return {'status': 'liked', 'likes': feedback['likes'] + 1}
        return {'status': 'error', 'message': 'you cannot like your own feedback'}
    return {'status': 'error', 'message': 'User not logged in'}

if __name__ == '__main__':
   
    app.run(host="127.0.0.1")
