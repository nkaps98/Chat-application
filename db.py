from datetime import datetime

import pymongo
from bson import ObjectId
from werkzeug.security import generate_password_hash
from user import User

try:
    mongo = pymongo.MongoClient(
        host="localhost",
        port=27017,
        serverSelectionTimeoutMS=100
    )

    db = mongo.company
    db2 = mongo.educollab_db
    mongo.server_info()
    rooms_collection = db.get_collection("rooms")
    room_members_collection = db.get_collection("room_members")
    messages_collection = db.get_collection("messages")
    permission_collection = db.get_collection("permissions")
    # trigger exception if it cannot connect to db
except:
    print("ERROR-Cannot connect to the db")


def save_users(username, email, password):
    password_hash = generate_password_hash(password)
    db.users.insert_one({'_id': username,
                         'email': email,
                         'password': password_hash
                         })


def get_users(username):
    user_data = db.users.find_one({'email': username})
    return User(user_data['_id'], user_data['email'], user_data['Password']) if user_data else None


def get_all_users():
    return list(db.users.find())


def save_room(room_name, created_by, usernames):
    room_id = rooms_collection.insert_one({
        'room_name': room_name,
        'created_by': created_by,
        'created_at': datetime.now(),
        'room_members': usernames,
        'messages': []
    }).inserted_id

    add_room_member(room_id, room_name, created_by, created_by, is_room_admin=True)
    return room_id


def update_room(room_id, room_name):
    rooms_collection.update_one({'_id': ObjectId(room_id)}, {'$set': {'name': room_name}})
    room_members_collection.update_many({'_id.room_id': ObjectId(room_id)}, {'$set': {'room_name': room_name}})


def get_room(room_id):
    return rooms_collection.find_one({'_id': ObjectId(room_id)})


def get_room_id(name):
    return rooms_collection.find_one({'room_name': name})


def add_room_member(room_id, room_name, username, added_by, is_room_admin=False):
    room_members_collection.insert_one({'_id': {'room_id': ObjectId(room_id), 'username': username},
                                        'room_name': room_name,
                                        'added_by': added_by,
                                        'added_at': datetime.now(),
                                        'is_room_admin': is_room_admin
                                        })


def add_room_members(room_id, room_name, usernames, added_by):
    room_members_collection.insert_many(
        [{'_id': {'room_id': ObjectId(room_id), 'username': username}, 'room_name': room_name, 'added_by': added_by,
          'added_at': datetime.now(), 'is_room_admin': False} for username in usernames]
    )


def remove_room_members(room_id, usernames):
    room_members_collection.delete_many(
        {'_id': {'$in': [{'room_id': room_id, 'username': usernames} for username in usernames]}})


def get_room_members(room_id):
    return list(room_members_collection.find({'_id.room_id': ObjectId(room_id)}))


def get_rooms_for_user(username):
    return list(rooms_collection.find({'room_members': {'$in': [username]}}))


def get_common_room(username, other_user):
    return list(rooms_collection.find({"$and": [
        {"room_members": {"$in": [username]}},
        {"room_members": {"$in": [other_user]}},
    ]}))


def is_room_member(room_id, username):
    return room_members_collection.count_documents({'_id': {'room_id': ObjectId(room_id), 'username': username}})


def is_room_admin(room_id, username):
    return room_members_collection.count_documents({'_id': {'room_id': ObjectId(room_id), 'username': username},
                                                    'is_room_admin': True})


def save_message(room_id, text, sender, receivers, status):
    message_id = messages_collection.insert_one({'room_id': room_id, "text": text, "sender": sender,
                                                 'receivers': receivers, 'created_at': datetime.now(),
                                                 'is_read': status}).inserted_id
    return message_id


def update_is_read(username, room):
    messages_collection.update_many({"$and": [
        {"receivers": {"$in": [username]}},
        {"room_id": room}
    ]}, {"$set": {"is_read": True}})


def get_messages(room_id):
    messages = list(messages_collection.find({'room_id': room_id}))
    for message in messages:
        message['created_at'] = message['created_at'].strftime('%d %b, %H:%M')
    return messages


def update_room_message(room_id, message):
    message_id = {'_id': ObjectId(message)}
    room_query = {'_id': ObjectId(room_id)}
    client = db['rooms']
    client.update(room_query, {"$push": {"messages": message_id}})


def delete_rooms(room_id):
    rooms_collection.delete_one({'_id': ObjectId(room_id)})


def delete_room_members(room_id):
    room_members_collection.delete_many({'_id.room_id': ObjectId(room_id)})


def find_message(message_id):
    return messages_collection.find_one({'_id': message_id})


def get_each_message(message_ids):
    message_list = []
    for id in message_ids:
        message = find_message(id['_id'])
        message['_id'] = str(message['_id'])
        message['created_at'] = str(message['created_at'])
        message_list.append(message)
    return message_list


def permission(username, other_name):
    permission_collection.insert_one({'_id': {'sent_by': username, 'sent_to': other_name},
                                      'status': ""
                                      })


def accept_permission(sent_to, sent_by, answer):
    permission_collection.update_one({"$and": [
        {'_id.sent_by': sent_by},
        {'_id.sent_to': sent_to},
    ]}, {'$set': {'status': answer}})


def decline_permission(sent_by):
    permission_collection.delete_one({'sent_to': sent_by})


def get_permission_db():
    return list(permission_collection.find())


def get_user_permissions(username):
    return list(permission_collection.find({"$and": [
        {"_id.sent_to": username},
        {"status": ""},
    ]}))


def find_unread_messages(username):
    return list(messages_collection.find({"receivers": {"$in": [username]},
                                          "is_read": False}))
