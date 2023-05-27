from pymongo import MongoClient
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
import datetime
import hashlib
from functools import wraps
from jwt import decode, InvalidTokenError, ExpiredSignatureError

app = Flask(__name__)
jwt = JWTManager(app)
app.config['JWT_SECRET_KEY'] = '38dd56f56d405e02ec0ba4be4607eaab'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1)

client = MongoClient('mongodb://localhost:27017')
db = client['SS-Forms']
users_collection = db['users']
texts_collection = db['texts']


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if the user is authenticated and has the 'isAdmin' role
        if 'Authorization' in request.headers:
            token = request.headers.get('Authorization').split()[1]
            try:
                payload = decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
                username = payload['sub']
                user_from_db = users_collection.find_one({'username': username})
                print(type(user_from_db['isAdmin']))
                if user_from_db and user_from_db['isAdmin'] == 'True':
                    return f(*args, **kwargs)
                else:
                    return jsonify(message='Admin access required'), 403  # Forbidden
            except ExpiredSignatureError:
                return jsonify(message='Token has expired'), 401  # Unauthorized
            except InvalidTokenError:
                return jsonify(message='Invalid token'), 401  # Unauthorized
        else:
            return jsonify(message='Missing authorization token'), 401  # Unauthorized

    return decorated_function


@app.route('/api/users', methods=['POST'])
def register():
    new_user = request.get_json()
    new_user['password'] = hashlib.sha256(new_user['password'].encode('utf-8')).hexdigest()
    doc = users_collection.find_one({'username': new_user['username']})
    if not doc:
        users_collection.insert_one(new_user)
        return jsonify({'msg': 'User created successfully'}), 201
    else:
        return jsonify({'msg': 'Username already exists'}), 409


@app.route('/api/users', methods=['GET'])
def get_users():
    result = users_collection.find()
    data = [
        {'_id': str(doc['_id']), 'username': doc['username'], 'isAdmin': doc['isAdmin'], 'password': doc['password']}
        for doc in result]
    return jsonify(data)


@app.route("/api/login", methods=["POST"])
def login():
    # Getting the login Details from payload
    login_details = request.get_json()  # store the json body request
    # Checking if user exists in database or not
    user_from_db = users_collection.find_one({'username': login_details['username']})  # search for user in database
    # If user exists
    if user_from_db:
        # Check if password is correct
        encrpted_password = hashlib.sha256(login_details['password'].encode("utf-8")).hexdigest()
        if encrpted_password == user_from_db['password']:
            # Create JWT Access Token
            access_token = create_access_token(identity=user_from_db['username'])  # create jwt token
            # Return Token
            return jsonify(access_token=access_token), 200
    return jsonify({'msg': 'The username or password is incorrect'}), 401


@app.route("/api/users/<username>", methods=["DELETE"])
def delete_user(username):
    # Check if the user exists
    user = users_collection.find_one({'username': username})
    if not user:
        return jsonify({'msg': 'User not found'}), 404

    # Delete the user from the 'users' collection
    users_collection.delete_one({'username': username})

    # Delete any associated texts/documents for the user from the 'texts' collection
    texts_collection.delete_many({'profile': username})

    return jsonify({'msg': 'User deleted successfully'}), 200


@app.route("/create", methods=["POST"])
@jwt_required()
def create_text():
    # Getting the user from access token
    current_user = get_jwt_identity()  # Get the identity of the current user
    user_from_db = users_collection.find_one({'username': current_user})

    # Checking if user exists
    if user_from_db:
        # Getting the text details from json
        text_details = request.get_json()  # store the json body request
        # Viewing if textd already present in collection
        user_text = {'profile': user_from_db["username"], "text": text_details["text"]}
        doc = texts_collection.find_one(user_text)  # check if user exist
        # Creating collection if not exists

        if not doc:
            texts_collection.insert_one(user_text)
            print("user_text ", user_text)
            return jsonify({'msg': 'text created successfully'}), 200
        # Returning message if text exists
        else:
            return jsonify({'msg': 'text already exists on your profile'}), 404
    else:
        return jsonify({'msg': 'Access Token Expired'}), 404


@app.route("/api/admin_only")
@admin_required
def admin_only_route():
    # Handle admin-only functionality here
    return jsonify(message='Admin-only endpoint')


@app.route("/get", methods=["GET"])
@jwt_required()
def get_text():
    # Getting the user from access token
    current_user = get_jwt_identity()  # Get the identity of the current user
    user_from_db = users_collection.find_one({'username': current_user})
    # Checking if user exists
    if user_from_db:
        # Viewing if textd already present in collection
        user_text = {'profile': user_from_db["username"]}
        return jsonify({"docs": list(db.texts.find(user_text, {"_id": 0}))}), 200
    else:
        return jsonify({'msg': 'Access Token Expired'}), 404


@app.route("/update", methods=["POST"])
@jwt_required()
def update_text():
    # Getting the user from access token
    current_user = get_jwt_identity()  # Get the identity of the current user
    user_from_db = users_collection.find_one({'username': current_user})

    # Checking if user exists
    if user_from_db:
        # Getting the text details from json
        text_details = request.get_json()  # store the json body request
        # Viewing if textd already present in collection
        user_text = {'profile': user_from_db["username"], "text": text_details["old_text"]}
        doc = texts_collection.find_one(user_text)  # check if user exist
        # Updating collection if not exists

        if doc:
            doc["text"] = text_details["new_text"]
            texts_collection.update_one(user_text, {"$set": {"text": doc["text"]}}, upsert=False)
            return jsonify({'msg': 'text Updated successfully'}), 200
        # Returning message if text exists
        else:
            return jsonify({'msg': 'text not exists on your profile'}), 404
    else:
        return jsonify({'msg': 'Access Token Expired'}), 404


@app.route("/delete", methods=["POST"])
@jwt_required()
def delete_text():
    """Creating the text with respect to the user
    Returns:
        dict: Return the profile and text created
    """
    # Getting the user from access token
    current_user = get_jwt_identity()  # Get the identity of the current user
    user_from_db = users_collection.find_one({'username': current_user})

    # Checking if user exists
    if user_from_db:
        # Getting the text details from json
        text_details = request.get_json()  # store the json body request
        # Viewing if textd already present in collection
        user_text = {'profile': user_from_db["username"], "text": text_details["text"]}
        doc = texts_collection.find_one(user_text)  # check if user exist
        # Creating collection if not exists

        if doc:
            texts_collection.delete_one(user_text)
            print("user_text ", user_text)
            return jsonify({'msg': 'text Deleted Sucessfully'}), 404
        # Returning message if text exists
        else:
            return jsonify({'msg': 'text not exists on your profile'}), 404
    else:
        return jsonify({'msg': 'Access Token Expired'}), 404