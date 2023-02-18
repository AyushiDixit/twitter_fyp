import pyodbc
from flask import Flask, render_template, request, redirect, url_for, session
import re
import bcrypt
import snscrape.modules.twitter as sntwitter
import pandas as pd
import joblib
import os
import re
from textblob import TextBlob
import sys
import matplotlib.pyplot as plt
import snscrape.modules.twitter as sntwitter
import datetime
import pandas as pd
import numpy as np
import snscrape.modules.twitter as sntwitter
import nltk
from nltk.sentiment.vader import SentimentIntensityAnalyzer


conn_str = ("Driver={ODBC Driver 17 for SQL Server};"
            "Server=DESKTOP-H17S9H6;"
            "Database=FYPtwitter;"
            "Trusted_Connection=yes;")
conn = pyodbc.connect(conn_str)
cursor = conn.cursor()

app = Flask(__name__)
app.secret_key = 'your secret key'


@app.route('/',methods=['GET', 'POST'])
def landingPage():
    # Check if user is loggedin
    msg = ''
    if 'logged_in' in session:
        if session['username'] != 'admin':
            return render_template('dashboard.html', username=session['username'])
        else : 
            return render_template('adminHome.html', username=session['username'])
    #contact us part
    if request.method == 'POST' and 'name' in request.form and 'email' in request.form and 'message' in request.form: 

        name = request.form['name']
        email = request.form['email']
        message = request.form['message']
        print(message)
        

        cursor.execute('INSERT INTO admin_contactUs VALUES(?,?,?)', (name, email, message,  ))
        conn.commit()
        msg ='success! we will contact you soon!'

    return render_template('landingPage.html', msg=msg)

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password'].encode()
        cursor.execute("SELECT * FROM userDetails WHERE username = ?" , (username, ))
        # Compare the hashed password
        account = cursor.fetchall()
        if account:
            stored_password = account[0][1]
            if bcrypt.checkpw(password, stored_password):
                print("Authentication successful")
                session['logged_in'] = True
                session['username'] = account[0][0]

                if session['username'] == 'admin':
                    return redirect(url_for('adm_records'))

                return redirect(url_for('home'))
            else:
                print("Authentication failed")
                msg = 'Incorrect username/password!'
        else: 
            msg = 'Incorrect username/password!'
    return render_template('index.html', msg=msg)

# http://localhost:5000/pythinlogin/home - this will be the home page, only accessible for loggedin users
@app.route('/home',methods=['GET', 'POST'])
def home():
    if 'logged_in' in session:
        if session['username'] != 'admin':
            username = session['username']
            cursor.execute('SELECT * FROM userDetails WHERE username = ?', (username,))
            account = cursor.fetchone()

            twit_user = account[0]
            #pull the values from database and then show on the dashboard or run the function everytime the generate report button is clicked
            cursor.execute('SELECT * FROM user_class_details where site_username =?', (username,))
            twitter_data = cursor.fetchall()
            print(twitter_data)

            positivet= twitter_data[0][0]
            negativen = twitter_data[0][1]
            neutraln= twitter_data[0][2]
            totalTrial = twitter_data[0][3]

            positive = percentage(positivet, totalTrial)
            negative = percentage(negativen, totalTrial)
            neutral = percentage(neutraln, totalTrial)
            positive = format(positive, '.1f')
            negative = format(negative, '.1f')
            neutral = format(neutral, '.1f')


            return render_template('dashboard.html', username=session['username'],totalTrial=totalTrial, neutral=neutral, positive=positive,negative=negative )
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))

@app.route('/adminhome')
def adminhome():
    msg = ''
    if session['username'] == 'admin':
        return render_template('adminHome.html', username= session['username'])
    else :
        msg = 'unauthorised access'
        return render_template('index.html', msg=msg)
        
# http://localhost:5000/python/logout - this will be the logout page
@app.route('/logout')
def logout():
    # Remove session data, this will log the user out
   session.pop('loggedin', None)
   session.pop('logged_in', None)
   session.pop('id', None)
   session.pop('username', None)
   session.pop('email', None)
   # Redirect to login page
   return redirect(url_for('login'))

# http://localhost:5000/pythinlogin/profile - this will be the profile page, only accessible for loggedin users
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'logged_in' in session:
        msg =''
        username = session['username']
        # We need all the account info for the user so we can display it on the profile page
        cursor.execute('SELECT * FROM userDetails WHERE username = ?', (username,))
        account = cursor.fetchone()
        # Show the profile page with account info
        return render_template('profile.html', account=account, msg=msg)
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))

@app.route('/update', methods=['GET', 'POST'])
def update():
    msg=''
    if 'logged_in' in session:
        if request.method == 'POST' and 'phone' in request.form and 'twitter_user_txt' in request.form :
            username = session['username']
            phone = request.form['phone']
            twt_user = request.form['twitter_user_txt']
            cursor.execute('UPDATE userDetails set phone = ? , twitter_username = ? WHERE username = ?', (phone, twt_user, username,))
            cursor.commit()
            return redirect(url_for('profile'))

        elif request.method == 'POST':
            msg = 'Please fill out the form !'
        # Show the profile page with account info
        else :
            username = session['username']
            cursor.execute('SELECT * FROM userDetails WHERE username = ?',(username))
            account = cursor.fetchone()
            print('not working')

        return render_template('update.html', account=account, msg=msg)
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))


@app.route('/changePassword', methods=['GET', 'POST'])
def changePW():
    if 'logged_in' in session:
        msg =''
        if session['username'] != 'admin':
            username = session['username']
            if request.method == 'POST' and 'old_password' in request.form and 'password' in request.form and 'new_password1' in request.form:
                if request.form['password'] == request.form['new_password1']:
                    oldpw = request.form['old_password'].encode()
                    #check if old pw matches 
                    cursor.execute('SELECT * FROM userDetails WHERE username = ?',(username))
                    account = cursor.fetchall()
                    stored_password = account[0][1]
                    if bcrypt.checkpw(oldpw, stored_password):
                        print("Authentication successful")
                        newpw = request.form['password'].encode()
                        salt = bcrypt.gensalt()
                        global hashed 
                        hashed = bcrypt.hashpw(newpw, salt)

                        cursor.execute('UPDATE userDetails set password = ?  WHERE username = ?', (hashed, username,))
                        cursor.commit()
                        msg = 'password successfully changed'
                        return render_template('changePW.html', msg=msg)
                    else : 
                        msg = 'invalid old password entered'
                        return render_template('changePW.html',  msg=msg)
                else : 
                    msg = 'new passwords dont match.'
                    return render_template('changePW.html',  msg=msg)
            else: 
                username = session['username']
                cursor.execute('SELECT * FROM userDetails WHERE username = ?',(username))
                account = cursor.fetchone()
            return render_template('changePW.html', account=account, msg=msg)
        return redirect(url_for('adminhome'))
    return redirect(url_for('login'))


# http://localhost:5000/pythinlogin/register - this will be the registration page, we need to use both GET and POST requests
@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:

        password = request.form['password'].encode()
        salt = bcrypt.gensalt()
        global hashed 
        hashed = bcrypt.hashpw(password, salt)
        username = request.form['username']
        #password = request.form['password']
        email = request.form['email']
        phone = request.form['phone']
        twit_user = request.form['twitter_user_txt']

        cursor.execute('SELECT * FROM userDetails WHERE username = ?', (username,))
        account = cursor.fetchone()
        cursor.execute('select * from userDetails where twitter_username = ?', (twit_user,))
        twitAccount = cursor.fetchone()
        # If account exists show error and validation checks
        if account:
            msg = 'Account already exists!'
        elif twitAccount: 
            msg = 'twitterUsername already exists'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers!'
        elif not username or not password or not email:
            msg = 'Please fill out the form!'
        else:

            limit = 70
            query_builder = "from:" + twit_user
            df_tweets = pd.DataFrame(searchScraper(query_builder, limit), columns=['date', 'twit_username', 'tweet'])
            status = 'none'
            if df_tweets.empty: 
                msg = 'Your twitter account must be public for this servive. '
            # Account doesnt exists and the form data is valid, now insert new account into accounts table
            else: 
                cursor.execute('INSERT INTO userDetails VALUES (?, ?, ?, ?, ?,?)', (username, hashed, email,phone,twit_user,status))
                conn.commit()
                limit = 70
                

                # build the SQL query
                table_name = 'tweets_store'
                columns = ', '.join(df_tweets.columns)
                values = ', '.join(['?' for i in range(len(df_tweets.columns))])
                query = f"INSERT INTO {table_name} ({columns}) VALUES ({values})"
                for row in df_tweets.itertuples(index=False):
                    cursor.execute(query, row)
                    conn.commit()

                #analyzinf and pusing first tweet data

                positive = 0
                negative = 0
                neutral = 0
                polarity = 0
                tweet_list = []
                neutral_list = []
                negative_list = []
                positive_list = []

                noOfTweet = len(df_tweets['tweet'])

                for tweet in df_tweets['tweet']:
                #print(tweet.text)
                    tweet_list.append(tweet)
                    analysis = TextBlob(tweet)
                    score = SentimentIntensityAnalyzer().polarity_scores(tweet)
                    neg = score['neg']
                    neu = score['neu']
                    pos = score['pos']
                    comp = score['compound']
                    polarity += analysis.sentiment.polarity
                
                    if neg > pos:
                        negative_list.append(tweet)
                        negative += 1
                    elif pos > neg:
                        positive_list.append(tweet)
                        positive += 1
                    
                    elif pos == neg:
                        neutral_list.append(tweet)
                        neutral += 1
                    
                positive = percentage(positive, noOfTweet)
                negative = percentage(negative, noOfTweet)
                neutral = percentage(neutral, noOfTweet)
                polarity = percentage(polarity, noOfTweet)
                positive = format(positive, '.1f')
                negative = format(negative, '.1f')
                neutral = format(neutral, '.1f')

                tweet_list = pd.DataFrame(tweet_list)
                neutral_list = pd.DataFrame(neutral_list)
                negative_list = pd.DataFrame(negative_list)
                positive_list = pd.DataFrame(positive_list)
                totalTrial = len(tweet_list)
                positiveT = len(positive_list)
                negTweets = len(negative_list)
                neutralTweets = len(neutral_list)
                print("total tweets: ",totalTrial)
                print("positive number: ",positiveT)
                print("negative number: ", negTweets)
                print("neutral number: ",neutralTweets)

                
                cursor.execute('INSERT INTO user_class_details VALUES(?,?,?,?,?,?)', (positiveT,negTweets,neutralTweets,totalTrial,twit_user, username,  ))
                conn.commit()
                

                msg = 'You have successfully registered! Proceed to sign in'
                return redirect(url_for('login'))
            

    else: 
        # Form is empty... (no POST data)
        msg = 'Please fill out the form!'
    # Show registration form with message (if any)
    return render_template('register.html', msg=msg)


@app.route('/record',methods=['GET', 'POST'])
def record():
    if 'logged_in' in session:
        username = session['username']
        cursor.execute('SELECT * FROM userDetails WHERE username = ?', (username,))
        account = cursor.fetchone()
        # Show the profile page with account info

        if request.method == 'POST':
            user_input = request.form['tweetSearch']
            print(user_input)
            query_builder = "from:" + user_input
            limit = 100
            # pull their tweets and put in a dataframe
            df = pd.DataFrame(searchScraper(query_builder, limit), columns=['Date', 'User', 'Tweet'])
            print(df)
            # clean the tweets
            df['Tweet_processed'] = df['Tweet'].apply(cleanText)
            new_df = df.loc[:, ['Date', 'User', 'Tweet']]
            # run the dataframe tweets with the model
            # load rf_model and vectorizer
            rf_model = joblib.load("./rf_model.joblib")
            vectorizer = joblib.load("./vectorizer.joblib")
            countDict = analyze_user(df, rf_model, vectorizer)
            # generate the data (positive/negative %)
            print('Analysis of twitter user: @' + user_input)
            print()
            print('Total number of tweets labeled as: ')
            print(countDict)
            print()
            print('Percentages of tweets labeled as: ')
            percentDict = getPercentDict(countDict)
            print(percentDict)
            print()
            print('Final classification of user (Negative/Neutral/Positive): ')
            classification = max(countDict, key=countDict.get)
            print(classification)

            positive_t = countDict["Positive"]
            negative_t = countDict["Negative"]


            positiveP = percentDict["Positive"]
            negativeP = percentDict["Negative"]
            print(positiveP)
            print(negativeP)



            return render_template('record.html',classification=classification, positive_t=positive_t, negative_t=negative_t, positiveP=positiveP, negativeP=negativeP, column_names=new_df.columns.values, row_data=list(new_df.values.tolist()),
                           link_column="User", zip=zip,)
        return render_template('record.html')
    return redirect(url_for('login'))



@app.route("/adminRecords", methods=["GET", "POST"])
def adm_records():
    if 'logged_in' in session:
        if session['username'] != 'admin':
            return render_template("error_cus.html")
        
        else : 

            # Search Feature
            if request.method == 'POST' and 'searchuserID' in request.form and (request.form['searchuserID'] != ""):
                search_user = request.form['searchuserID']

                cursor.execute('SELECT * FROM userDetails where username = ?  ', (search_user,))
                data = cursor.fetchall()

                return render_template("adminRecords.html", data=data)

            if request.method == 'POST' and 'manage_button' in request.form:
                user = (request.form['manage_button'])
                return redirect(url_for('adm_manage_records', user=user))
        
        #if suspend button is pressed
            if request.method == 'POST' and 'suspend_button' in request.form:
                user = (request.form['suspend_button'])

            #set status to suspend
            #cursor.execute("UPDATE userDetails SET status='Suspended' where username = ?", (user,))
            #mysql.connection.commit()
            
            #delete user from userDetails
                cursor.execute('DELETE from userDetails WHERE username = ?',(user,))
                conn.commit()
                cursor.execute('DELETE from user_class_details where site_username = ?', (user,))
                conn.commit()
            

            cursor.execute("SELECT * FROM userDetails WHERE username NOT LIKE 'admin'")
            data = cursor.fetchall()

            return render_template("adminRecords.html", data=data)
    return redirect(url_for('login'))
    
@app.route("/adminManageRecords", methods=["GET", "POST"])
def adm_manage_records():

    # Check if user is loggedin
    if 'logged_in' in session:

        #declare variables
        data = ""
        search_user = ""
        search_condition=""
        msg = ""

        #getting user from GET 
        if(request.args.get('user')):
            search_user = request.args.get('user')
            cursor.execute('SELECT * from userDetails where username = ?', (search_user,))
            data = cursor.fetchone()

        #processing data
        if request.method == 'POST':

            #when search button is pressed, retrieve data
            if 'searchuserID' in request.form and request.form['searchuserID'] != "":
                if(search_condition == ""):
                    search_condition = request.form['searchuserID']
                    session['search_user'] = search_condition
                    cursor.execute('SELECT * FROM userDetails where username = ?', (search_condition,))
                    data = cursor.fetchone()
            
            #when update button is pressed
            if 'update_button' in request.form:
                if 'search_user' in session:
                    search_user = session['search_user']

                #check if fields empty
                if request.form['username'] != "" and request.form['email'] != "" and request.form['phone_num'] != "" and request.form['twitter_user_txt'] != "" and request.form['sub_status'] != "":
                    
                    #retrieve variables from form
                    sysID = request.form["SysID"]
                    email = request.form["email"]
                    phone = request.form["phone_num"]
                    username = request.form["username"]
                    twt_handle = request.form["twitter_user_txt"]
                    status = request.form["sub_status"]
                    print(search_user)
                    print(username)

                    #update user details
                    cursor.execute('UPDATE userDetails SET username = ?, email = ?, phone = ?, twitter_username = ?, status = ? WHERE username = ?', (username, email, phone, twt_handle, status, search_user,))
                    conn.commit()
                    cursor.execute('update user_class_details set site_username = ?', (username,))

                    msg = "user successfully updated"
                    session.pop('search_user', None)
                    return render_template("adminRecords.html", data="", msg=msg)
                
                else:
                    msg = "please search for a user and enter blank fields"
            
            #when suspend button is clicked
            if 'suspend_button' in request.form:
                #check if username empty
                if request.form["username"] != "":
                    sysID = request.form["SysID"]
                    username = request.form["username"]

                    #update user details (status to suspend)
                    #cursor.execute('UPDATE userDetails SET status = ? WHERE username = ?', ('suspended', username,))
                    #mysql.connection.commit()

                    #delete user from userDetails
                    cursor.execute('DELETE from userDetails WHERE username = ?',(username,))
                    conn.commit()

                    msg = "user successfully suspended"
                    return render_template("adminManageRecords.html", data="", msg=msg)

                else:
                    msg = "please search for a user"
            
        return render_template("adminManageRecords.html", search_condition= search_condition, data=data, msg=msg)
    
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))

@app.route("/adminMessage", methods=["GET", "POST"])
def admMessage():
    if 'logged_in' in session:
        if session['username'] != 'admin':
            return render_template("error_cus.html")
        
        else : 
            cursor.execute("SELECT * FROM admin_contactUs")
            data = cursor.fetchall()

            if 'suspend_button' in request.form:
                #check if username empty
                
                    
                    username = request.form["name"]

                    #update user details (status to suspend)
                    #cursor.execute('UPDATE userDetails SET status = ? WHERE username = ?', ('suspended', username,))
                    #mysql.connection.commit()

                    #delete user from userDetails
                    cursor.execute('DELETE from userDetails WHERE username = ?',(username,))
                    conn.commit()

                    msg = "user successfully suspended"
                    return render_template("adminMessageRecord.html", data="", msg=msg)

            return render_template("adminMessageRecord.html", data=data)
    return redirect(url_for('login'))


def percentage(part,whole):
 return 100 * float(part)/float(whole)

# function for pulling tweets
def searchScraper(query, limit):
    tweets = []
    for tweet in sntwitter.TwitterSearchScraper(query, top=True).get_items():
        if len(tweets) == limit:
            break
        else:
            tweets.append([tweet.date, tweet.user.username, tweet.content])
    return tweets

# function for data pre-processing
def cleanText(text):
    text = re.sub(r'@[A-Za-z0-9_]+', '', text) # Remove @mentions
    text = re.sub(r'#', '', text) # Remove # symbol
    text = re.sub(r'RT[\s]+', '', text) # Remove RT
    text = re.sub(r'https?:\/\/\S+', '', text) # Remove hyperlink
    return text

# function to analyse sentiment for a SINGLE TWEET
def analyze_sentiment(text, model, vectorizer):
    scoreDict = {}
    features = vectorizer.transform([text]).toarray()
    prediction = model.predict_proba(features)
    positive_prob = prediction[0][1] * 100
    negative_prob = prediction[0][0] * 100
    scoreDict['Positive'] = positive_prob
    scoreDict['Negative'] = negative_prob
    scoreLabel = max(scoreDict, key=scoreDict.get)
    return scoreDict, scoreLabel, positive_prob,  negative_prob

# function to analyse user's sentiment as a whole
def analyze_user(df, model, vectorizer):
    # init variables and dictionary
    negative_count = 0
    neutral_count = 0
    positive_count = 0
    for tweet in df['Tweet_processed']:
        scoreDict, scoreLabel, positive_prob, negative_prob = analyze_sentiment(tweet, model, vectorizer)
        # individual label count
        if scoreLabel == 'Negative':
            negative_count += 1
        elif scoreLabel == 'Neutral':
            neutral_count += 1
        elif scoreLabel == 'Positive':
            positive_count += 1
    countDict = {'Negative': negative_count, 'Positive': positive_count}
    return countDict
        

def getPercentDict(countDict):
    percentDict = {}
    for key, value in countDict.items():
        rounded_value = round((value * 100 / sum(countDict.values())), 2)
        string = str(rounded_value) + '%'
        percentDict[key] = string
    return percentDict
        # individual label count



 