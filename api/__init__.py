from flask import Flask, jsonify, make_response, request
from bson import json_util, ObjectId
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)
from flask_bcrypt import Bcrypt
import json

from .extensions import mongo

app = Flask(__name__)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)

config_object='api.settings'
app.config.from_object(config_object)

mongo.init_app(app)

@app.route('/', methods=['GET'])
def index():
    return '<h1>APi Works</h1>'


@app.route('/register', methods=['POST'])
def register():
    # Check if the user made the request with JSON
    if not request.is_json:
        return jsonify({ "msg": "Missing JSON in Request"}), 400

    # Check if the user included deviceid and password in the request
    deviceid = request.json.get('deviceid', None)
    password = request.json.get('password', None)
    if not deviceid:
        return jsonify({"msg": "Missing deviceid parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400
    
    # Check if an account doesn't already exist
    user_collection = mongo.db.users
    user = user_collection.find_one({ 'deviceid': deviceid })
    if user is not None:
        return jsonify({ "msg": "Device already has an account"}), 401

    # Hash the password
    pwhash = bcrypt.generate_password_hash(password).decode('utf-8')
    newUser = {
        'deviceid': deviceid,
        'password': pwhash,
        'liked': []
    }
    id = user_collection.insert(newUser)
    token = create_access_token(identity=str(id))
    return jsonify(jwt=token), 200

@app.route('/login', methods=['POST'])
def login():
    # Check if the user made the request with JSON
    if not request.is_json:
        return jsonify({ "msg": "Missing JSON in Request"}), 400

    # Check if the user included deviceid and password in the request
    deviceid = request.json.get('deviceid', None)
    password = request.json.get('password', None)
    if not deviceid:
        return jsonify({"msg": "Missing deviceid parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400
    
    # Check if the account actually exists
    user_collection = mongo.db.users
    user = user_collection.find_one({ 'deviceid': deviceid })
    if user is None:
        return jsonify({ "msg": "Account does not exist"}), 401

    # Compare passwords
    compare = bcrypt.check_password_hash(user['password'], password)
    if compare == False:
        return jsonify({ "msg": "Incorrect password"}), 401
    
    token = create_access_token(identity=str(user.get('_id')))
    return jsonify(jwt=token), 200
    #return json.dumps(user, indent=4, default=json_util.default)

@app.route('/testauth', methods=['GET'])
@jwt_required
def protected():
    user = get_jwt_identity()
    return jsonify(deviceid=user), 200

@app.route('/all', methods=['GET'])
@jwt_required
def allPosts():
    # Check if the user made the request with JSON
    if not request.is_json:
        return jsonify({ "msg": "Missing JSON in Request"}), 400

    # Check that a msg and location was included in the post
    lat = request.json.get('lat', None)
    lng = request.json.get('lng', None)
    if not lat:
        return jsonify({"msg": "Missing latitude \"lat\" of the post"}), 400
    if not lng:
        return jsonify({"msg": "Missing longitude \"lng\" of the post"}), 400
    
    # Make sure lat and lng are numbers
    try:
        float(lat)
    except ValueError:
        return jsonify({"msg": "Latitude is not a float" }), 400
    try:
        float(lng)
    except ValueError:
        return jsonify({"msg": "Longitude is not a float"}), 400

    # Get the post collection
    post_collection = mongo.db.posts

    # This is a geospatial query where in centerSphere: Index 0 of the array
    # represents the geographical coordinate we're retrieving positions relative to.
    # Index 1 of the array represents 5 (miles) divided by the radius of the earth
    # (A radian conversion), to get all posts within a 5 mile radius 
    posts = post_collection.find({ 
                'location': {
                    '$geoWithin': { 
                        '$centerSphere': [
                            [float(lat), float(lng)],
                            5 / 3963.2
                        ]
                    } 
                }
            }
            , {'_id': False, 'user': False })
    
    return jsonify(posts=[doc for doc in posts])

@app.route('/post', methods=['GET', 'POST'])
@jwt_required
def post():
    # get the userid and post collection
    user = get_jwt_identity()
    post_collection = mongo.db.posts

    if request.method == 'POST':
        # Check if the user made the request with JSON
        if not request.is_json:
            return jsonify({ "msg": "Missing JSON in Request"}), 400

        # Check that a msg and location was included in the post
        msg = request.json.get('msg', None)
        lat = request.json.get('lat', None)
        lng = request.json.get('lng', None)
        if not msg:
            return jsonify({"msg": "Missing message of the post"}), 400
        if not lat:
            return jsonify({"msg": "Missing latitude \"lat\" of the post"}), 400
        if not lng:
            return jsonify({"msg": "Missing longitude \"lng\" of the post"}), 400

        # Make sure lat and lng are numbers
        try:
            float(lat)
        except ValueError:
            return jsonify({"msg": "Latitude is not a float" }), 400
        try:
            float(lng)
        except ValueError:
            return jsonify({"msg": "Longitude is not a float"}), 400

        # create the post
        newPost = {
            'user': ObjectId(user),
            'post': msg,
            'likes': 0,
            'location': {
                'type': "Point",
                'coordinates': [float(lat), float(lng)]
            },
            'comments': []
        }

        # insert the new post into the post collections
        post_collection.insert(newPost)

    # Query for the users posts
    user_posts = post_collection.find({ "user": ObjectId(user) }, {'_id': False, 'user': False })

    return jsonify(posts=[doc for doc in user_posts])
    #return json.dumps(user_posts, indent=4, default=json_util.default)

@app.route('/post/like/<string:postid>', methods=['PUT', 'DELETE'])
@jwt_required
def like_post(postid):
    #check if the post exists
    post_collection = mongo.db.posts
    post = post_collection.find_one({ '_id': ObjectId(postid)})
    if post is None:
        return jsonify({ "msg": "Post does not exist" }), 400
    
    # get the user
    user = get_jwt_identity()
    user_collection = mongo.db.users
    userdoc = user_collection.find_one({ '_id': ObjectId(user) })
    if userdoc is None:
        return jsonify({ "msg": "Error retrieving user account" }), 400

    if request.method == 'PUT':
        # check if the user liked, add postid to their liked array, then save
        for post in userdoc["liked"]:
            if post == postid:
                return jsonify({ "msg": "You have already liked this post" }), 401
        userdoc["liked"].append(postid)
        user_collection.save(userdoc)

        # add a like to the post and save
        post["likes"] += 1
        post_collection.save(post)
    
    if request.method == 'DELETE':
        # delete the post from the user's liked array and save
        if postid in userdoc["liked"]:
            del userdoc["liked"][userdoc["liked"].index(postid)]
        user_collection.save(userdoc)

        # remove a like from the post and save
        post["likes"] -= 1
        post_collection.save(post)

    #return jsonify({ "msg": "You have successfully liked this post" }), 200
    return json.dumps(post, indent=4, default=json_util.default)

#THIS isn't test yet but probably works xd
@app.route('/post/comment/<string:postid>', methods=['GET', 'POST'])
@jwt_required
def comment_post(postid):
    #check if the post exists
    post_collection = mongo.db.posts
    post = post_collection.find_one({ '_id': ObjectId(postid)})
    if post is None:
        return jsonify({ "msg": "Post does not exist" }), 400
    
    # get the user
    user = get_jwt_identity()
    user_collection = mongo.db.users
    userdoc = user_collection.find_one({ '_id': ObjectId(user) })
    if userdoc is None:
        return jsonify({ "msg": "Error retrieving user account" }), 400
    
    if request.method == 'POST':
        # Check if the user made the request with JSON
        if not request.is_json:
            return jsonify({ "msg": "Missing JSON in Request"}), 400

        # Check that comment was included in the post
        comment = request.json.get('comment', None)
        if not comment:
            return jsonify({"msg": "Missing the comment"}), 400
        post.comments.append(comment)

        #save the post
        post_collection.save(post)
    
    #return the comments of the post
    return jsonify({"comments": post.comments}), 200