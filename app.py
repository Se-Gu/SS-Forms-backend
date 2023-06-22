from pymongo import MongoClient
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
import datetime
import hashlib
from functools import wraps
from jwt import decode, InvalidTokenError, ExpiredSignatureError
from bson.json_util import dumps
from bson.objectid import ObjectId
import uuid

app = Flask(__name__)
CORS(app)
jwt = JWTManager(app)
app.config['JWT_SECRET_KEY'] = '38dd56f56d405e02ec0ba4be4607eaab'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1)

client = MongoClient('mongodb+srv://ss-forms:hVue0GPTLC5tGOLP@cluster0.bf3pr6v.mongodb.net/')
db = client['user_forms']
users_collection = db['users']
forms_collection = db['forms']

def user_from_request(request):
    token = request.headers.get('Authorization').split()[1]
    payload = decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
    username = payload['sub']
    user_from_db = users_collection.find_one({'username': username})
    return user_from_db
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if the user is authenticated and has the 'isAdmin' role
        if 'Authorization' in request.headers:
            try:
                user_from_db = user_from_request(request)
                if user_from_db and user_from_db['isAdmin']:
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

@app.route('/api/users/admin', methods=['POST'])
def admin_register():
    new_user = request.get_json()
    new_user['password'] = hashlib.sha256(new_user['password'].encode('utf-8')).hexdigest()
    new_user['isAdmin'] = True
    users_collection.insert_one(new_user)
    return jsonify({'msg': 'Admin user created successfully'}), 201


@app.route('/api/users', methods=['POST'])
def register():
    new_user = request.get_json()
    new_user['password'] = hashlib.sha256(new_user['password'].encode('utf-8')).hexdigest()
    new_user['isAdmin'] = False
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
        {'_id': str(doc['_id']),
         'username': doc['username'],
         'isAdmin': doc.get('isAdmin', False)}  # Use doc.get() to handle missing 'isAdmin' field
        for doc in result
    ]
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
            # Return Token and isAdmin status
            return jsonify(access_token=access_token, isAdmin=user_from_db['isAdmin'],username=user_from_db['username']), 200
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

# CRUD operations for the "forms" collection
@app.route('/api/forms', methods=['POST'])
@admin_required
def create_form():
    # Inserts a new form into the "forms" collection and returns its generated ID
    form_data = request.get_json()
    form = forms_collection.find_one({'formName': form_data['formName']})
    if form:
        return jsonify({'msg': 'Form with name already exists'}), 404
    else:
        form_id = str(uuid.uuid4())  # Generate a UUID for the form
        form_data['id'] = form_id
        forms_collection.insert_one(form_data)
        return jsonify({'msg': 'Form creation successful'}), 201

@app.route('/api/forms/<form_id>', methods=['GET'])
@admin_required
def get_form(form_id):
    # Retrieves a form by its ID from the "forms" collection
    form = forms_collection.find_one({'id': form_id})
    if form:
        form_data = dumps(form)
        return form_data, 200, {'Content-Type': 'application/json'}
    return jsonify({'msg': 'Form not found'}), 404

@app.route('/api/forms', methods=['GET'])
def get_all_forms():
    # Retrieves all forms from the "forms" collection
    forms = forms_collection.find()
    #print(dumps(forms))
    if forms:
        forms_data = dumps(forms)
        return forms_data, 200, {'Content-Type': 'application/json'}
    return jsonify({'msg': 'No forms found'}), 404

@app.route('/api/forms/<form_id>', methods=['PUT'])
@admin_required
def update_form(form_id):
    updated_data = request.get_json()
    print(updated_data)
    # Updates a form in the "forms" collection with the provided ID
    forms_collection.update_one({'id': form_id}, {'$set': updated_data})
    return jsonify({'msg': 'Form updated successfully'})

@app.route('/api/forms/<form_id>', methods=['DELETE'])
@admin_required
def delete_form(form_id):
    # Deletes a form from the "forms" collection with the provided ID
    forms_collection.delete_one({'id': form_id})
    return jsonify({'msg': 'Form deleted successfully'})

# CRUD operations for the "formQuestions" field
@app.route('/api/forms/<form_id>/questions', methods=['POST'])
@admin_required
def add_question(form_id):
    question_data = request.get_json()
    question_id = str(uuid.uuid4())  # Generate a UUID for the question
    question_data['id'] = question_id
    # Adds a new question to the "formQuestions" array within a form
    forms_collection.update_one({'id': form_id}, {'$push': {'formQuestions': question_data}})
    return jsonify({'msg': 'Question added successfully'})

@app.route('/api/forms/<form_id>/questions/<question_id>', methods=['PUT'])
@admin_required
def update_question(form_id, question_id):
    updated_data = request.get_json()
    # Updates a question within the "formQuestions" array of a form
    forms_collection.update_one({'id': form_id, 'formQuestions.id': question_id},
                                {'$set': {'formQuestions.$': updated_data}})
    return jsonify({'msg': 'Question updated successfully'})

@app.route('/api/forms/<form_id>/questions/<question_id>', methods=['DELETE'])
@admin_required
def delete_question(form_id, question_id):
    # Deletes a question from the "formQuestions" array of a form
    forms_collection.update_one({'id': form_id}, {'$pull': {'formQuestions': {'id': question_id}}})
    return jsonify({'msg': 'Question deleted successfully'})

# CRUD operations for the "formResponses" field
@app.route('/api/forms/<form_id>/responses', methods=['POST'])
@jwt_required()
def add_response(form_id):
    response_data = request.get_json()
    user = user_from_request(request)
    updated = False
    for answer_data in response_data:
        question_id = answer_data['questionId']
        print(question_id)
        answer = answer_data.get('answer', None)
        answer_data = {
            'id': str(uuid.uuid4()),
            'userId': user['_id'],
            'username': user['username'],
            'answer': answer
        }

        existing_answer = forms_collection.find_one(
            {
                'id': form_id,
                'formQuestions': {
                    '$elemMatch': {
                        'id': question_id,
                        'answers': {
                            '$elemMatch': {
                                'userId': user['_id']
                            }
                        }
                    }
                }
            },
            {'formQuestions.$': 1}
        )

        if existing_answer:
            #print(answer_data)
            print(existing_answer)
            updated = True
            forms_collection.update_one(
                {'id': form_id, 'formQuestions.id': question_id, 'formQuestions.answers.userId': user['_id']},
                {'$set': {'formQuestions.$.answers.$[elem].answer': answer}},
                array_filters=[{'elem.userId': user['_id']}]
            )
        else:
            forms_collection.update_one(
                {'id': form_id, 'formQuestions.id': question_id},
                {'$push': {'formQuestions.$.answers': answer_data}}
            )
    if not updated:
        return jsonify({'msg': 'Response added successfully'})
    else:
        return jsonify({'msg': 'Response updated successfully'})


@app.route('/api/forms/<form_id>/responses/<response_id>', methods=['PUT'])
@jwt_required()
def update_response(form_id, response_id):
    updated_data = request.get_json()
    question_id = updated_data['questionId']
    answer = updated_data['answer']

    forms_collection.update_one(
        {'id': form_id, 'formQuestions.id': question_id, 'formQuestions.answers.id': response_id},
        {'$set': {'formQuestions.$.answers.$.answer': answer}}
    )

    return jsonify({'msg': 'Response updated successfully'})


@app.route('/api/forms/<form_id>/responses/<response_id>', methods=['DELETE'])
@jwt_required()
def delete_response(form_id, response_id):
    forms_collection.update_one(
        {'id': form_id, 'formQuestions.answers.id': response_id},
        {'$pull': {'formQuestions.$.answers': {'id': response_id}}}
    )

    return jsonify({'msg': 'Response deleted successfully'})


@app.route("/api/admin_only")
@admin_required
def admin_only_route():
    # Handle admin-only functionality here
    return jsonify(message='Admin-only endpoint')


@app.route('/')
def hello():
    return "Hello, this is the backend application!"



app.debug=True

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
