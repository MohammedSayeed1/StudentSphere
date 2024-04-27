
from flask import Flask, render_template, request, jsonify
from textblob import TextBlob
from nltk.tokenize import word_tokenize
from nltk.corpus import opinion_lexicon
import nltk
from flask_cors import CORS
from flask_cors import cross_origin
from flask import Response
import json

app = Flask(__name__, static_url_path='/static')
CORS(app)

import mysql.connector

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/project')
def project():
    return render_template('project.html')

@app.route('/quiz')
def quiz():
    return render_template('quiz.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/admindash')
def admindash():
    return render_template('admindash.html')
@app.route('/quizreport')
def quizreport():
    return render_template('quizreport.html')


@app.route('/analyze', methods=['POST'])
@cross_origin()
def analyze():
    text = request.form['text']
    username = request.form['username']
    reg_number = request.form['reg_number']
    batch = request.form['batch']


    # Initialize TextBlob for sentiment analysis
    blob = TextBlob(text)

    # Get the sentiment score
    sentiment_score = blob.sentiment.polarity

    # Determine the sentiment label based on the sentiment score
    sentiment = 'Positive' if sentiment_score > 0 else 'Negative'

    # Therapist advice based on sentiment
    therapist_advice = ''
    if sentiment == 'Positive':
        therapist_advice = "You are doing good. Enjoy your day!"
    else:
        therapist_advice = "Please consider visiting a therapist."

    # Use NLTK's opinion lexicon to count positive and negative words in the input text
    positive_lexicon = set(opinion_lexicon.positive())
    negative_lexicon = set(opinion_lexicon.negative())
    tokens = word_tokenize(text.lower())  # Tokenize the text
    positive_count = sum(1 for token in tokens if token in positive_lexicon)
    negative_count = sum(1 for token in tokens if token in negative_lexicon)

    # Calculate the total number of words
    total_words = len(tokens)

    # Calculate the percentage of positive and negative words
    positive_percentage = (positive_count / total_words) * 100
    negative_percentage = (negative_count / total_words) * 100

    # Create a dictionary to hold the results
    results = {
        'text': text,
        'sentiment': sentiment,
        'positive_count': positive_count,
        'negative_count': negative_count,
        'positive_percentage': positive_percentage,
        'negative_percentage': negative_percentage,
        'therapist_advice': therapist_advice
    }
        # Establish a connection to the MySQL database
    connection = mysql.connector.connect(
        host='localhost',
        user='root',
        password='Sayeed$1504',
        database='login credentials',
        port=3306
    )
    if connection.is_connected():
        print('Connected to MySQL database')

    # Create a cursor object to execute SQL queries
        cursor = connection.cursor()
        
        insert_query = """
        INSERT INTO analysis (username, reg_number, batch, feelingsInput, sentiment, positive_count, negative_count, positive_percentage, negative_percentage, therapist_advice)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """

        # Data tuple for insertion
        data = (username, reg_number, batch, text, sentiment, positive_count, negative_count, positive_percentage, negative_percentage, therapist_advice)

        try:
            # Execute the SQL query with data
            cursor.execute(insert_query, data)

            # Commit the changes to the database
            connection.commit()

            print(f'{cursor.rowcount} record inserted successfully.')

        except mysql.connector.Error as error:
            print('Error:', error)

        finally:
            # Close cursor and connection
            cursor.close()
            connection.close()
            print('MySQL connection closed')

    else:
        print('Connection to MySQL database failed')
        print(results)
    # Pass the sentiment analysis results, word counts, and therapist advice back to the project.html template
    return render_template('project.html', text=text, sentiment=sentiment, 
                           positive_count=positive_count,
                           negative_count=negative_count,
                           positive_percentage=positive_percentage,
                           negative_percentage=negative_percentage,
                           therapist_advice=therapist_advice)
    

@app.route('/quizans', methods=['POST'])
def quizans():
    text = request.form['text']
    username = request.form['username']
    reg_number = request.form['reg_number']
    batch = request.form['batch']


    # Initialize TextBlob for sentiment analysis
    blob = TextBlob(text)

    # Get the sentiment score
    sentiment_score = blob.sentiment.polarity

    # Determine the sentiment label based on the sentiment score
    sentiment = 'Positive' if sentiment_score > 0 else 'Negative'

    # Therapist advice based on sentiment
    therapist_advice = ''
    if sentiment == 'Positive':
        therapist_advice = "You are doing good. Enjoy your day!"
    else:
        therapist_advice = "Please consider visiting a therapist."

    # Use NLTK's opinion lexicon to count positive and negative words in the input text
    positive_lexicon = set(opinion_lexicon.positive())
    negative_lexicon = set(opinion_lexicon.negative())
    tokens = word_tokenize(text.lower())  # Tokenize the text
    positive_count = sum(1 for token in tokens if token in positive_lexicon)
    negative_count = sum(1 for token in tokens if token in negative_lexicon)

    # Calculate the total number of words
    total_words = len(tokens)

    # Calculate the percentage of positive and negative words
    positive_percentage = (positive_count / total_words) * 100
    negative_percentage = (negative_count / total_words) * 100

    # Create a dictionary to hold the results
    results = {
        'text': text,
        'sentiment': sentiment,
        'positive_count': positive_count,
        'negative_count': negative_count,
        'positive_percentage': positive_percentage,
        'negative_percentage': negative_percentage,
        'therapist_advice': therapist_advice
    }
        # Establish a connection to the MySQL database
    connection = mysql.connector.connect(
        host='localhost',
        user='root',
        password='Sayeed$1504',
        database='login credentials',
        port=3306
    )
    if connection.is_connected():
        print('Connected to MySQL database')

    # Create a cursor object to execute SQL queries
        cursor = connection.cursor()
        
        insert_query = """
        INSERT INTO analysis (username, reg_number, batch, feelingsInput, sentiment, positive_count, negative_count, positive_percentage, negative_percentage, therapist_advice)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """

        # Data tuple for insertion
        data = (username, reg_number, batch, text, sentiment, positive_count, negative_count, positive_percentage, negative_percentage, therapist_advice)

        try:
            # Execute the SQL query with data
            cursor.execute(insert_query, data)

            # Commit the changes to the database
            connection.commit()

            print(f'{cursor.rowcount} record inserted successfully.')

        except mysql.connector.Error as error:
            print('Error:', error)

        finally:
            # Close cursor and connection
            cursor.close()
            connection.close()
            print('MySQL connection closed')

    else:
        print('Connection to MySQL database failed')
        print(results)
    # Pass the sentiment analysis results, word counts, and therapist advice back to the project.html template
    return render_template('project.html', text=text, sentiment=sentiment, 
                           positive_count=positive_count,
                           negative_count=negative_count,
                           positive_percentage=positive_percentage,
                           negative_percentage=negative_percentage,
                           therapist_advice=therapist_advice)
    



if __name__ == '__main__':
    app.run(debug=True)