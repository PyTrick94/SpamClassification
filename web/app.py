from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt, json, requests, os, io
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from pandas import DataFrame
import numpy as np


app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.ImageRecognition  # creating new db
users = db["Users"]  # creating new collection


def UserExist(username):
    if users.find({"Username": username}).count() == 0:
        return False
    else:
        return True


class Register(Resource):
    def post(self):
        posted_data = request.get_json()

        username = posted_data["username"]
        password = posted_data["password"]

        if UserExist(username):
            ret_json = {
                "status": 301,
                "message": "Invalid Username"
            }
            return ret_json

        hashed_pw = bcrypt.hashpw(password.encode("utf8"), bcrypt.gensalt())

        users.insert({"Username": username,
                      "Password": hashed_pw,
                      "Tokens": 4
                      })

        ret_json = {
            "status": 200,
            "message": "You successfully signed up for this API"
        }
        return ret_json


def verify_pw(username, password):
    if not UserExist(username):
        return False  # if not not (if not not exists)

    hashed_pw = users.find({
        "Username": username
    })[0]["Password"]

    if bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
        return True
    else:
        return False


def jsonGenerator(status, msg):
    ret_json = {
        "status": status,
        "message": msg
    }
    return ret_json


def verifyCredentials(username, password):
    if not UserExist(username):
        return jsonGenerator(301, "Invalid Username"), True  # error

    correct_pw = verify_pw(username, password)
    if not correct_pw:
        return jsonGenerator(302, "Invalid password"), True

    return None, False


def readFiles(path):
    for root, dirnames, filenames in os.walk(path):
        for i in filenames:
            path = os.path.join(root, i)

            tekst = False
            lines = []
            f = io.open(path, 'r', encoding='latin1')
            for line in f:
                if tekst:  # skip first row
                    lines.append(line)
                elif line == '\n':
                    tekst = True
            f.close()
            message = '\n'.join(lines)
            yield path, message


def dataFrameFromDirectory(path, classification):
    rows = []
    index = []
    for filename, message in readFiles(path):
        rows.append({'message': message, 'class': classification})
        index.append(filename)
        return DataFrame(rows, index=index)


class Classify(Resource):
    def post(self):
        posted_data = request.get_json()

        username = posted_data["username"]
        password = posted_data["password"]
        example = posted_data["example"]

        li = []
        li.append(example)

        ret_json, error = verifyCredentials(username, password)

        if error:
            return jsonify(ret_json)

        tokens = users.find({"Username": username})[0]["Tokens"]

        if tokens <= 0:
            return jsonify(jsonGenerator("303", "Not Enough Tokens"))

        data = DataFrame({'message': [], 'class': []})
        work_path = os.getcwd()
        spam = os.path.join(work_path, 'spam')
        ham = os.path.join(work_path, 'ham')

        data = data.append(dataFrameFromDirectory(spam, 'spam'))
        data = data.append(dataFrameFromDirectory(ham, 'ham'))

        vectorizer = CountVectorizer()
        counts = vectorizer.fit_transform(data['message'].values)  # conv words into num; matrix "word:count"
        classifier = MultinomialNB()  # creates list of words of each email and nr of occurs
        targets = data['class'].values  # targets - data classification
        classifier.fit(counts, targets)  # NB model
        example_counts = vectorizer.transform(li)  # convert to the same data format as model has
        predictions = classifier.predict(example_counts)

        prediction = ''
        prediction = prediction.join(predictions)

        users.update({
            "Username": username
        }, {
            "$set": {"Tokens": tokens - 1}
        })

        ret_json = {
            "status": 200,
            "prediction": str(prediction),
            "tokens" : tokens
        }

        return jsonify(ret_json)


class Refill(Resource):
    def post(self):
        posted_data = request.get_json()

        username = posted_data["username"]
        password = posted_data["admin_pw"]
        amount = posted_data["amount"]

        if not UserExist(username):
            return jsonify(jsonGenerator(301, "Invalid Username"))

        correct_pw = "sample123"

        if not correct_pw == password:
            return jsonify(jsonGenerator(304, "Invalid Admin Password"))

        tokens = users.find({"Username": username})[0]["Tokens"]

        users.update({
            "Username": username
        }, {
            "$set": {
                "Tokens": tokens + amount
            }
        })

        return jsonify(jsonGenerator(200, "Refill succeed"))


api.add_resource(Register, "/register")
api.add_resource(Classify, "/classify")
api.add_resource(Refill, "/refill")

if __name__ == "__main__":
    app.run(host="0.0.0.0")