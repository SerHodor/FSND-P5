from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask import flash
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Category, Base, Item, User
from htmlmin import minify

from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests


app = Flask(__name__)
# connect to the database
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
# get client secrets
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog"


@app.route('/login')
def showLogin():
    # logout if user is already logged in
    if 'username' in login_session:
        return redirect(url_for("gdisconnect"))
    # Generate anti-forgery token
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template("loginPage.html", STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        print "error is here"
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['type'] = "gplus"

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 200px; height: 200px;border-radius: 100px;-webkit-border-radius: 100px;-moz-border-radius: 100px;"> '
    return output

# User Helper Functions


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session['access_token']
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session[
        'access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        # delete login_session
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['type']
        del login_session['user_id']
        return render_template("logout.html")
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

# homepage : Display all items


@app.route('/')
@app.route('/catalog/')
def homePage():
    loggedin = False
    if 'user_id' in login_session:
        loggedin = True
    cats = session.query(Category).all()
    output = render_template("homePage.html",
                             cats=cats,
                             loggedin=loggedin)
    return minify(output)


@app.route('/catalog/<string:category_name>/')
@app.route('/catalog/<string:category_name>/items/')
def categoryPage(category_name):
    # check if user is logged in
    loggedin = False
    if 'user_id' in login_session:
        loggedin = True
    cats = session.query(Category).all()
    cat = session.query(Category).filter_by(name=category_name).one()
    items = session.query(Item).filter_by(category_id=cat.id).all()
    return render_template("categoryPage.html",
                           cats=cats,
                           items=items,
                           category_name=category_name,
                           loggedin=loggedin)


@app.route('/catalog/<string:category_name>/<string:item_name>/')
def itemPage(category_name, item_name):
    category = session.query(Category).filter_by(name=category_name).one()
    item = session.query(Item).filter_by(category_id=category.id,
                                         name=item_name).one()
    # check if user is logged in
    loggedin = False
    if 'user_id' in login_session:
        loggedin = True
    # if user is allowed to modify the content
    access = False
    if 'user_id' in login_session:
        if item.user_id == login_session['user_id']:
            access = True
    return render_template("itemPage.html",
                           item=item,
                           access=access,
                           category_name=category_name,
                           loggedin=loggedin)


@app.route('/catalog/addNewItem/', methods=['GET', 'POST'])
def addItemPage():
    if request.method == 'POST':
        # check if user is logged in
        if 'user_id' not in login_session:
            return redirect(url_for("showLogin"))
        # add new item
        category_name = request.form['category_name']
        item_name = request.form['name']
        itemAlreadyExists = False
        try:
            category = session.query(Category).filter_by(
                name=category_name).one()
            item = session.query(Item).filter_by(category_id=category.id,
                                                 name=item_name).one()
            if item.name == item_name:
                itemAlreadyExists = True
        except:
            pass
        if itemAlreadyExists:
            return "Item with this name already exists in same category"
        else:
            category = session.query(Category).filter_by(
                name=category_name).one()
            item = Item(name=item_name,
                        description=request.form['description'],
                        category=category,
                        user_id=login_session['user_id'])
            session.add(item)
            session.commit()
            return redirect(url_for("itemPage",
                                    category_name=category_name,
                                    item_name=item_name))
    else:
        # check if user is logged in
        if 'user_id' not in login_session:
            return redirect(url_for("showLogin"))
        # display add new item form
        cats = session.query(Category).all()
        return render_template("addItemPage.html", cats=cats)


@app.route('/catalog/<string:category_name>/<string:item_name>/edit/',
           methods=['GET', 'POST'])
def editItemPage(category_name, item_name):
    if request.method == 'POST':
        category = session.query(Category).filter_by(name=category_name).one()
        item = session.query(Item).filter_by(
            category_id=category.id, name=item_name).one()
        # check if user is allowed to edit the content
        if 'user_id' not in login_session:
            return redirect(url_for("showLogin"))
        if item.user_id != login_session['user_id']:
            return "You are not authorized to access this page"
        # make changes
        new_category_name = request.form['category_name']

        itemAlreadyExists = False
        try:
            new_category = session.query(Category).filter_by(
                name=new_category_name).one()
            item = session.query(Item).filter_by(
                category_id=new_category.id,
                name=request.form['name']).one()
            if item.name == item_name:
                itemAlreadyExists = True
        except:
            pass
        if itemAlreadyExists:
            return "Item with this name already exists in choosen category"

        item.name = request.form['name']
        item.description = request.form['description']
        item.category = session.query(
            Category).filter_by(name=category_name).one()
        session.commit()
        return redirect(url_for("itemPage",
                                category_name=item.category.name,
                                item_name=item.name))
    else:

        category = session.query(Category).filter_by(name=category_name).one()
        item = session.query(Item).filter_by(
            category_id=category.id, name=item_name).one()
        # check if user is allowed to edit the content
        if 'user_id' not in login_session:
            return redirect(url_for("showLogin"))
        if item.user_id != login_session['user_id']:
            return "You are not authorized to access this page"
        # fetch edit form
        cats = session.query(Category).all()
        return render_template("editItemPage.html", item=item, cats=cats)


@app.route('/catalog/<string:category_name>/<string:item_name>/delete/',
           methods=['GET', 'POST'])
def deleteItemPage(category_name, item_name):
    if request.method == 'POST':
        cat = session.query(Category).filter_by(name=category_name).one()
        item = session.query(Item).filter_by(
            category_id=cat.id, name=item_name).one()
        # check if user is allowed to delete the content
        if 'user_id' not in login_session:
            return redirect(url_for("showLogin"))
        if item.user_id != login_session['user_id']:
            return "You are not authorized to access this page"
        # delete the item
        session.delete(item)
        session.commit()
        return redirect(url_for("categoryPage",
                                category_name=category_name))
    else:
        cat = session.query(Category).filter_by(name=category_name).one()
        item = session.query(Item).filter_by(
            category_id=cat.id, name=item_name).one()
        # check if user is allowed to delete the content
        if 'user_id' not in login_session:
            return redirect(url_for("showLogin"))
        if item.user_id != login_session['user_id']:
            return "You are not authorized to access this page"
        # make delete option available
        return render_template("deleteItemPage.html", item=item, cat=cat)

# JSON Endpoints

# 1. Endpoint for complete catalog data


@app.route('/json/')
@app.route('/catalog/json/')
def jsonCatalog():
    cats = session.query(Category).all()
    # JSON = []
    # for cat in cats:
    # 	catJSON = cat.serialize
    # 	items = session.query(Item).filter_by(category_id=cat.id).all()
    # 	catJSON["Item"] = [i.serialize for i in items]
    # 	JSON.append(catJSON)
    # return jsonify(Category=JSON)
    return jsonify(Catalog=[cat.serialize for cat in cats])

# 2. Endpoint for category data


@app.route('/catalog/<string:category_name>/json/')
@app.route('/catalog/<string:category_name>/items/json/')
def jsonCategory(category_name):
    items = session.query(Category).filter_by(name=category_name)
    return jsonify(Category=[item.serialize for item in items])

# 3. Endpoint for each item data seperately


@app.route('/catalog/<string:category_name>/<string:item_name>/json/')
def jsonItem(category_name, item_name):
    cat = session.query(Category).filter_by(name=category_name).one()
    item = session.query(Item).filter_by(
        category_id=cat.id, name=item_name).one()
    return jsonify(Item=[item.serialize])


if __name__ == '__main__':
    app.secret_key = 'HodorHoDor'
    app.debug = True
    app.run(host='0.0.0.0', port=8080)
