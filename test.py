import mysql.connector
from mysql.connector import connection
from flask import Flask, request, render_template

app = Flask(__name__)
cnx = connection.MySQLConnection(user='test', password='789789',
                                 host='127.0.0.1',
                                 database='tweet')
cnx.close()

@app.route("/")
def index():
    # return "working"
    return render_template("index.html")

@app.route("/create", methods=["GET", "POST"])
def create():
    if request.method == "POST":
        # Add code here to insert a new record into your database
        return redirect(url_for("index"))
    return render_template("create.html")

@app.route("/read/<id>")
def read(id):
    # Add code here to retrieve the record from your database
    return render_template("read.html", record=record)

@app.route("/update/<id>", methods=["GET", "POST"])
def update(id):
    if request.method == "POST":
        # Add code here to update the record in your database
        return redirect(url_for("index"))
    # Add code here to retrieve the record from your database
    return render_template("update.html", record=record)

@app.route("/delete/<id>", methods=["GET", "POST"])
def delete(id):
    if request.method == "POST":
        # Add code here to delete the record from your database
        return redirect(url_for("index"))
    # Add code here to retrieve the record from your database
    return render_template("delete.html", record=record)

if __name__ == "__main__":
    app.run(debug=True)
