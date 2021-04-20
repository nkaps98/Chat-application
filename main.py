import json
from datetime import datetime

from bson import json_util
from flask import Flask, render_template, redirect, request, url_for, request, flash, Response, make_response
from flask_socketio import SocketIO, join_room, leave_room
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from pymongo.errors import DuplicateKeyError

from db import get_users, save_users, save_room, add_room_members, get_rooms_for_user, get_room, is_room_member, \
    get_room_members, is_room_admin, update_room, remove_room_members, save_message, get_messages, update_room_message, \
    get_room_id, delete_room_members, delete_rooms, get_each_message, get_all_users, permission, accept_permission, \
    decline_permission, get_permission_db, get_common_room, get_user_permissions, \
    find_unread_messages, update_is_read

app = Flask(__name__)
app.secret_key = 'my secret key'
socketio = SocketIO(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

count=0
connected_users = {}

@app.route('/')
def home():
    all_users = []
    if current_user.is_authenticated:
        permissions = get_user_permissions(current_user.username)
        users = get_all_users()
        for user in users:
            room = get_common_room(user, current_user.username)
            if user['_id']!=current_user.username:
                all_users.append(user)
    else:
        users=''
    return render_template('index.html', users=all_users, permissions=permissions, username=current_user.username)


@app.route('/user_profile/<name>', methods=['GET', 'POST'])
@login_required
def user_profile(name):
    user_profile_name = name
    room = get_common_room(name, current_user.username)
    if room != []:
        room = room[0]['_id']
    else:
        room=""
    return render_template('user_profile.html', room=room, user_profile_name=user_profile_name,
                           username=current_user.username)

@app.route('/login', methods=['GET', 'POST'])
def login():
    '''
    Login api for the chat application
    :return: the user is taken to the main page of the application
    '''
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    message = ''
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = get_users(username)
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            message = 'Failed to login'

    return render_template('login.html', message=message)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    message = ''
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        try:
            save_users(username, email, password)
            return redirect(url_for('login'))
        except DuplicateKeyError:
            message = 'User already exists!'

    return render_template('signup.html', message=message)


@app.route('/logout', methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/delete-room', methods=['GET', 'POST'])
@login_required
def delete_room():
    message=''
    if request.method == 'POST':
        room_name = request.form.get('room_name')
        room_id = get_room_id(room_name)['_id']
        room_admin = is_room_admin(room_id, current_user.username)
        if room_name and room_admin:
            delete_room_members(room_id)
            delete_rooms(room_id)
        else:
            message='You are not authorised to delete this room'
    return render_template('delete_room.html', message=message)

def create_room(user1, user2):
    '''
    This function executes once the user accepts the connection
    request sent by other users. Once the room is created the user
    is able to chat with the user
    :param user1: the user that sent the request
    :param user2: user that accepted the request
    '''
    global count
    room_name = 'room' + str(count)
    count+=1
    usernames = [user1, user2]
    for user in usernames:
        user_info = get_users(user)
        if not user_info:
            return "Enter valid user"
    if len(room_name) and len(usernames):
        room_id = save_room(room_name, user1, usernames)
        if user1 in usernames:
            usernames.remove(user1)
        add_room_members(room_id, room_name, usernames, user1)
        redirect(url_for('view_room', room_id=room_id))
    else:
        message = 'Failed to create room'
    return render_template('index.html')

@app.route('/chat_history/<room_name>/', methods=['GET', 'POST'])
@login_required
def chat_history(room_name):
    room_id = get_room_id(room_name)['_id']
    rooms = get_room(room_id)
    messages = get_each_message(rooms['messages'])
    return Response(json.dumps(messages), mimetype='application/json',status=200)

@app.route('/rooms/<room_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_room(room_id):
    '''
    add new room members to the room, this functionality will
    come later when groups are made for multiple users
    :param room_id: id of room created in the rooms collection
    :return: connects the page to the edit room html page
    '''
    room = get_room(room_id)
    if room and is_room_admin(room_id, current_user.username):
        existing_room_members = [member['_id']['username'] for member in get_room_members(room_id)]
        room_members_str = ','.join(existing_room_members)
        message = ''
        if request.method == 'POST':
            room_name = request.form.get('room_name')
            room['name'] = room_name
            update_room(room_id, room_name)

            new_members = [username.strip() for username in request.form.get('members').split(',')]
            members_to_add = list(set(new_members) - set(existing_room_members))
            members_to_remove = list(set(existing_room_members)-set(new_members))

            if len(members_to_add):
                add_room_members(room_id, room_name, members_to_add, current_user.username)

            if len(members_to_remove):
                remove_room_members(room_id, members_to_remove)
            message='Room edited successfully'
            room_members_str = ','.join(new_members)
        return render_template('edit_room.html', room=room, room_members_str=room_members_str, message=message)
    else:
        return "Room not found", 404
@app.route('/rooms/<room_id>')
@login_required
def view_room(room_id):
    '''
    This api shows all the previous messages sent by both the users
    and provides a webpage where users can communicate
    :param room_id: id of room created in the database
    :return: connects the api to the view room webpage
    '''
    rooms=[]
    room = get_room(room_id)
    if room and is_room_member(room_id, current_user.username):
        room_members = get_room_members(room_id)
        messages = get_messages(room_id)
        room_list = get_rooms_for_user(current_user.username)
        return render_template("view_room.html",username=current_user.username,room=room, room_members=room_members,
                               messages=messages, rooms=room_list)
    else:
        return "Room not found", 404

@app.route('/send-request/<name>', methods=['GET', 'POST'])
@login_required
def send_request(name):
    '''
    the user when clicks the send request button, the request is saved in the
    permission collection with status parameter initially being empty
    :param name: name of the user to whom the request is to be sent
    :return: redirects user to the home page
    '''
    if request.method=='POST':
        data = {}
        if get_users(name):
            permission(current_user.username, name)
            data['username'] = current_user.username
    return redirect(url_for('home'))

@app.route('/invitation/<sent_by>/<answer>', methods=['GET', 'POST'])
@login_required
def receive_request(sent_by, answer):
    '''
    the user when clicks Accept/Decline button is redirected to this api
    When user clicks accept, the status parameter in permissions is updated to
    accept
    if user clicks decline, that permission/request gets deleted from the
    permission collection in the database
    :param sent_by: name/id of the user that sent the request
    :param answer: accept/decline
    :return: redirects the user to the home page
    '''
    answer = answer
    sent_by = sent_by
    sent_to = current_user.username
    if current_user.username == sent_to:
        if answer == 'accept':
            accept_permission(sent_to, sent_by, 'accept')
            create_room(sent_by, sent_to)
        elif answer == 'decline':
            decline_permission(sent_to)
        return redirect(url_for('home'))
    else:
        return "you are not authorized"

## Websocket APIs

@socketio.on('send_message')
@login_required
def handle_send_message_event(data):
    '''
    when user clicks the send message button, javascript function send the
    message details to this api. If the receiver of the message is present in
    the room, it stores the message in the message collection with is_read parameter True

    if the receiver is currently not present in the room, the message is saved to message
    collection with is_read to False and if the user is present in some other chat with another user
    the message is sent to that room. If the user is not present in any room the message is sent to
    the '/notif' namespace.
    :param data: information about the user that joined the room
    :return:
    '''
    global connected_users
    app.logger.info("{} has sent message to the room {}:{}".format(
        data['username'],
        data['room'],
        data['message']
    ))
    room_name = data['room']
    data['created_at'] = datetime.now().strftime("%d %b, %H:%M")
    room_members = get_room_members(data['room'])
    receivers = [username['_id']['username'] for username in room_members]
    receivers.remove(data['username'])
    data['receivers'] = receivers
    # checks whether user is present in any room
    if receivers[0] in connected_users[data['room']]:
        # since the receiver of the message is in the room, it marks is_read = True
        message_id = save_message(data['room'], data['message'], data['username'], data['receivers'],
                              True)
    else:
        # since the receiver of the message is in the room, it marks is_read = False
        rec = []
        message_id = save_message(data['room'], data['message'], data['username'], data['receivers'],
                                  False)
        # checks whether the receiver is present in any room
        for user in connected_users:
            if receivers[0] in connected_users[user]:
                data['room'] = user
                rec.append(user)
        # if the user is not present in any room and is on other pages, it sends the message to the
        # client on the '/notifs' namespace
        if rec == []:
            # sends response to javascript function socket.on('send_notification')
            # in user_profile and index html pages
            socketio.emit('send_notification', data, namespace='/notifs')
        else:
            # if the user is present in the room it sends the message ti the client in that room
            # sends response to javascript function socket.on('send_notification')
            socketio.emit('send_notification', data, room=data['room'])
    update_room_message(room_name, message_id)
    socketio.emit('receive_message', data, room=z)

@socketio.on('join_room')
@login_required
def handle_join_room_event(data):
    '''
    This api is activated when the user joins the room. The server stores the information
    that user has joint the room and in response sends the join room annoucements that lets
    the other user know that the client has joined the room
    :param data: information about the user that joined the room
    :return: sends notification to the room that user has joined the room
    '''
    app.logger.info("{} has joined the room {}".format(
        data['username'],
        data['room']
    ))
    global connected_users
    # appends user to the dictionary connected_users.
    # if the room id is in the connected users, it appends the user that has just joined
    # the room to that rooms active users list
    if data['room'] in connected_users:
        connected_users[data['room']].add(data['username'])
    # if the room id is not in the connected users, it creates a new key with room id and stores
    # the user that has joined the room in a list
    else:
        connected_users[data['room']] = {data['username']}
    data['connected_users'] = list(connected_users[data['room']])
    unread_messages = find_unread_messages(data['username'])
    if unread_messages:
        update_is_read(data['username'], data['room'])

    # socketio function which stores the user that has joined the room in the server
    join_room(data['room'])

    # sends response to javascript function socket.on('join_room_announcement')
    socketio.emit('join_room_announcement', data, room=data['room'])

@socketio.on('notification')
@login_required
def handle_notification_event(data):
    '''
    when some other user sends message to the current user not present in the room, it retrieves the
    unread messages for the current user and sends the notification for the latest unread message to the
    current user chatting with someone else.
    :param data: contains the message and receivers id
    '''
    unread_messages = find_unread_messages(data['username'])
    data['unread_messages'] = get_each_message(unread_messages)

    # sends response to javascript function socket.on('receive_notification') in view_room.html
    socketio.emit('receive_notification', data, room=data['room'])


@socketio.on('notification_outside', namespace='/notifs')
@login_required
def handle_notification_event(data):
    '''
    when some other user sends message to the current user not present in the room, it retrieves the
    unread messages for the current user and sends the notification for the latest unread message
    :param data: contains the message and receivers id
    '''
    unread_messages = find_unread_messages(data['username'])
    data['unread_messages'] = get_each_message(unread_messages)
    data['receivers'] = data['unread_messages'][-1]['receivers'][0]
    data['last_message'] = data['unread_messages'][-1]['text']

    # sends response to javascript function socket.on('receive_notification') in index and user profile
    # html pages
    socketio.emit('receive_notification', data, namespace='/notifs')

@socketio.on('send_permission', namespace='/notifs')
def handle_permission_event(data):
    '''
    When the user sends request to another user it saves the request in the permission collection with status
    being empty initially
    :param data: the current username and the receivers name
    :return:
    '''
    permission(data['username'], data['receive_name'])
    permissions = get_user_permissions(data['receive_name'])
    data['permission'] = permissions
    data['last_permission'] = permissions[-1]

    # sends response to javascript function socket.on('receive_permission')
    socketio.emit('receive_permission', data, namespace='/notifs')


@socketio.on('leave_room')
@login_required
def handle_leave_room_event(data):
    '''
    This api is activated when the user leaves the room. The server stores the information
    that user has left the room and in response sends the join room annoucements that lets
    the other user know that the client has left the room
    :param data: information about the user that left the room
    :return: sends notification to the room that user has left the room
    '''
    global connected_users
    app.logger.info("{} has left the room {}".format(
        data['username'],
        data['room']
    ))
    if data['room'] in connected_users:
        connected_users[data['room']].remove(data['username'])
    data['connected_users'] = list(connected_users[data['room']])
    leave_room(data['room'])
    socketio.emit('leave_room_announcement', data, room=data['room'])


@login_manager.user_loader
def load_user(username):
    return get_users(username)

if __name__ == '__main__':
    socketio.run(app, debug=True)
