import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    #obtain balance from wallet
    balanceExtract = (db.execute("SELECT * FROM users WHERE id=?", session["user_id"]))
    balance = balanceExtract[0]["cash"]

    #obtain table with Shares position
    usernameExtract = db.execute('SELECT * FROM users WHERE id=?', session["user_id"])
    username = usernameExtract[0]['username']
    summary = db.execute('SELECT * FROM ?', username)

    #update prices of tables
    for row in summary:
        symbolCheck=row['symbol']
        quoteList = lookup(symbolCheck)
        price = quoteList['price']
        db.execute("UPDATE ? SET price=? WHERE symbol=?", username, price, symbolCheck)

    #obtaining summary updated and preparing data to send to page
    summary = db.execute('SELECT * FROM ?', username)
    total=balance
    for rows in summary:
        total+=(rows['shares']*rows['price'])

    return render_template("index.html", summary=summary, balance=usd(balance), total=usd(total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST": #second time accessing it
        # Ensure symbol and shares are submitted and are valid
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        if not symbol or not shares:
            return apology("Missing symbol or shares")
        if not testInt(shares):
            return apology("Shares are not valid", 400)
        shares=int(shares)
        if shares<0:
            return apology("Shares can't be negative", 400)

        #robtain list from web and check validation:
        quoteList = lookup(symbol)
        if quoteList==None:
            return apology("Invalid symbol")

        #if symbol is valid, proceed to process purchase
        shareName=quoteList['name']
        price = quoteList['price']
        symbolCheck = quoteList['symbol']

        #check if user have enough cash
        balanceExtract = (db.execute("SELECT * FROM users WHERE id=?", session["user_id"]))
        balance = balanceExtract[0]["cash"]
        newBalance = balance-(price*shares)
        if newBalance<0:
            return apology("Not enough balance to complete this process.")
        #update new balance for user
        db.execute("UPDATE users SET cash = ? WHERE id=?", newBalance, session["user_id"])
        #Update Transactions table (TODO)

        #Update shares of user
        usernameExtract = db.execute('SELECT * FROM users WHERE id=?', session["user_id"])
        username = usernameExtract[0]['username']
        sharesInWalletExtract = db.execute('SELECT * FROM ? WHERE symbol=?', username, symbolCheck)
        if not sharesInWalletExtract: #in case this Share is not included yet
            db.execute("INSERT INTO ? (symbol, name, shares, price) VALUES(?, ?, ?, ?)", username, symbolCheck, shareName, shares, price)
        else: #in case user already have this Share in his wallet
            newSharesInWallet = sharesInWalletExtract[0]['shares']+shares
            db.execute("UPDATE ? SET shares=?, price=? WHERE symbol=?", username, newSharesInWallet, price, symbolCheck)
        return redirect("/")

    #accessing first time this page
    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST": #second time accessing it
        # Ensure symbol was submitted
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Missing symbol")

        #robtain list from web and check validation:
        quoteList = lookup(symbol)
        if quoteList==None:
            return apology("Invalid symbol")

        #if symbol is valid, proceed to quoted page
        shareName=quoteList['name']
        price = quoteList['price']
        symbolCheck = quoteList['symbol']
        return render_template("quoted.html", shareName=shareName, symbol=symbolCheck, price=usd(price))

    #accessing first time this page
    return render_template("quote.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST": #second time accessing it
        # Ensure username was submitted
        username = request.form.get("username")
        if not username:
            return apology("must provide username", 400)
        #if username already exists return apology
        user=db.execute("SELECT username FROM users WHERE username=?", username)
        if user:
            return apology("Username already exists", 400)

        # Ensure password was submitted
        elif not request.form.get("password") or not request.form.get("confirmation"):
            return apology("must provide password and confirmation", 400)
        # Ensure password was re-entered correctly
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("Re-entered password does not match.", 400)

        # # After validating input, must insert in database
        # username = request.form.get("username")
        passHash = generate_password_hash(request.form.get("password"))
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, passHash)

        #create User Wallet's table
        db.execute("CREATE TABLE ? (id INTEGER, symbol TEXT NOT NULL, name TEXT NOT NULL, shares NUMERIC NOT NULL, price NUMERIC NOT NULL, PRIMARY KEY(id))", username)

        #create Transactions table (TODO)

        # Redirect user to home page
        return redirect("/")

    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # acquiring username
    usernameExtract = db.execute('SELECT * FROM users WHERE id=?', session["user_id"])
    username = usernameExtract[0]['username']

    if request.method == "POST": #second time accessing it
        # Ensure symbol and shares are submitted and are valid
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        if not symbol or not shares:
            return apology("Missing symbol or shares")
        if not testInt(shares):
            return apology("Shares are not valid", 400)
        shares=int(shares)
        if shares<0:
            return apology("Shares can't be negative", 400)
        #check if user have enough shares to sell
        sharesExtract = (db.execute("SELECT * FROM ? WHERE symbol=?", username, symbol))
        sharesFromUser = sharesExtract[0]["shares"]
        if not sharesFromUser:
            return apology("Not found those shares owned to sell", 400)
        if sharesFromUser<shares:
            return apology("Not enough shares to sell", 400)

        #update new balance for user
        balanceExtract = (db.execute("SELECT * FROM users WHERE id=?", session["user_id"]))
        balance = balanceExtract[0]["cash"]
        priceFromUser = sharesExtract[0]["price"]
        newBalance = balance+(priceFromUser*shares)
        db.execute("UPDATE users SET cash = ? WHERE id=?", newBalance, session["user_id"])

        #Update Transactions table (TODO)

        #Update shares of user
        newShares = sharesFromUser-shares
        if newShares==0: #If shares are going to be zero, must remove entire row
            db.execute('DELETE FROM ? WHERE symbol=?', username, symbol)
        else: #in case the share will just be updated
            db.execute("UPDATE ? SET shares=? WHERE symbol=?", username, newShares, symbol)
        return redirect("/")

    #accessing first time this page
    symbols=db.execute('SELECT symbol FROM ?', username)
    return render_template("sell.html", symbols=symbols)

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

def testInt(number):
    try:
       int(number)
       return True
    except:
        return False