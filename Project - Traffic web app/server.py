# !/usr/bin/env python

# import the various libraries needed
import http.cookies as Cookie  # some cookie handling support
from http.server import BaseHTTPRequestHandler, HTTPServer  # the heavy lifting of the web server
import urllib  # some url parsing support
import base64  # some encoding support
import secrets
from hashlib import sha256
import sqlite3


def access_database(dbfile, query, *par):
    """Query the local database provided. Takes any number of query input parameters"""

    connect = sqlite3.connect(dbfile)
    cursor = connect.cursor()
    if par == ():
        cursor.execute(query)
    else:
        cursor.execute(query, par)
    connect.commit()
    connect.close()


def access_database_with_result(dbfile, query, *par):
    """Query the local database provided and return the results.
    Takes any number of query input parameters"""

    connect = sqlite3.connect(dbfile)
    cursor = connect.cursor()
    if par == ():
        rows = cursor.execute(query).fetchall()
    else:
        rows = cursor.execute(query, par).fetchall()
    connect.commit()
    connect.close()
    return rows


def hash_password(password):
    """return a hashed password from a password input using the hashlib module"""
    h_pass = sha256()
    password = bytes(password, 'utf-8')
    h_pass.update(password)
    hashed_password = h_pass.hexdigest()

    return hashed_password


def build_response_refill(where, what):
    """This function builds a refill action that allows part of the
    currently loaded page to be replaced."""
    text = "<action>\n"
    text += "<type>refill</type>\n"
    text += "<where>"+where+"</where>\n"
    m = base64.b64encode(bytes(what, 'ascii'))
    text += "<what>"+str(m, 'ascii')+"</what>\n"
    text += "</action>\n"
    return text


def build_response_redirect(where):
    """This function builds the page redirection action
    It indicates which page the client should fetch.
    If this action is used, only one instance of it should
    contained in the response and there should be no refill action."""
    text = "<action>\n"
    text += "<type>redirect</type>\n"
    text += "<where>"+where+"</where>\n"
    text += "</action>\n"
    return text


# Decide if the combination of user and magic is valid
def handle_validate(iuser, *imagic):
    """Validates the current session. If being called by the logon function without a session cookie,
    checks to see whether there is an open session already in the system for that user.
    Otherwise checks if the user and session id are part of an open session."""
    if imagic == ():
        # check if the function is being called by the logon action
        open_sessions = access_database_with_result("trafficdb.db",
                                                    """SELECT COUNT(*) from sessions
                                                    where username = ? and end_time IS NULL""",
                                                    iuser)[0][0]
        # if session is empty, there are no other logons in the system
        return bool(open_sessions == 0)
    else:
        open_sessions = access_database_with_result("trafficdb.db",
                                                    """SELECT COUNT(*) from sessions
                                                    where username = ? and session_id = ? and end_time IS NULL""",
                                                    iuser, imagic[0])[0][0]
        return bool(open_sessions != 0)


# remove the combination of user and magic from the data base, ending the login
def handle_delete_session(iuser, imagic):  # removed second arg imagic from here
    """Ends a users previous login session by adding an end time to the session in the db
    if attempting to login as a different user."""
    access_database("trafficdb.db",
                    """UPDATE sessions set end_time = datetime('now','localtime')
                    where username = ? AND session_id = ? and end_time is NULL""",
                    iuser, imagic)


# A user has supplied a username (parameters['usernameinput'][0])
# and password (parameters['passwordinput'][0]) check if these are
# valid and if so, create a suitable session record in the database
# with a random magic identifier that is returned.
# Return the username, magic identifier and the response action set.
def handle_login_request(iuser, imagic, parameters):
    """Checks to see if the credentials supplied are valid.
    Validates the login attempt, and updates the db with a new session if so."""
    text = "<response>\n"

    # check if login details are mising
    try:
        usercheck = access_database_with_result("trafficdb.db",
                                                """SELECT count(*) from users
                                                where username = ? and password = ?""",
                                                parameters['usernameinput'][0], hash_password(parameters['passwordinput'][0]))
        if 0 in usercheck[0]:
            text += build_response_refill('message', 'Login details not found')
            user = '!'
            magic = ''
        else:
            new_user = parameters['usernameinput'][0]

            if handle_validate(new_user) is False:
                text += build_response_refill('message', 'User already logged in')
                user = iuser
                magic = imagic
            else:
                user = parameters['usernameinput'][0]
                magic = secrets.token_urlsafe()
                handle_delete_session(iuser, imagic)
                access_database("trafficdb.db",
                                """INSERT INTO sessions (session_id,username, start_time)
                                VALUES(?,?,datetime('now','localtime'))""",
                                magic, user)

                text += build_response_redirect('/page.html')

    except KeyError as miss:
        if miss.args[0] == 'passwordinput':
            text += build_response_refill('message', 'Password missing')
        elif miss.args[0] == 'usernameinput':
            text += build_response_refill('message', 'Username missing')
        else:
            text += build_response_refill('message', 'Error with login details')
        user = '!'
        magic = ''

    text += "</response>\n"
    return [user, magic, text]


# The user has requested a vehicle be added to the count
# parameters['locationinput'][0] the location to be recorded
# parameters['occupancyinput'][0] the occupant count to be recorded
# parameters['typeinput'][0] the type to be recorded
# Return the username, magic identifier (these can be empty  strings) and the response action set.
def handle_add_request(iuser, imagic, parameters):
    """Adds the requested entry to the database."""
    text = "<response>\n"
    if handle_validate(iuser, imagic) is not True:
        # Invalid sessions redirect to login
        text += build_response_refill('message', 'Error, login session not valid')
    else:
        try:
            access_database("trafficdb.db",
                            """INSERT INTO traffic_data
                            VALUES(?, ?, ?, datetime('now','localtime'), ?, ?, 0)""",
                            parameters['locationinput'][0], parameters['typeinput'][0], parameters['occupancyinput'][0], iuser, imagic
                            )
            text += build_response_refill('message', 'Entry added.')

        except Exception:
            text += build_response_refill('message', 'Location cannot be empty')

    count = str(access_database_with_result("trafficdb.db",
                                            """SELECT COUNT(*) FROM traffic_data
                                            WHERE undo_flag = 0 AND session_id = ?""",
                                            imagic
                                            )[0][0]
                )
    text += build_response_refill('total', count)
    text += "</response>\n"
    user = ''
    magic = ''
    return [user, magic, text]


# The user has requested a vehicle be removed from the count
# This is intended to allow counters to correct errors.
# parameters['locationinput'][0] the location to be recorded
# parameters['occupancyinput'][0] the occupant count to be recorded
# parameters['typeinput'][0] the type to be recorded
# Return the username, magic identifier (these can be empty  strings) and the response action set.
def handle_undo_request(iuser, imagic, parameters):
    """Removes the matching entry from the database"""
    text = "<response>\n"

    if handle_validate(iuser, imagic) is not True:
        # Invalid sessions redirect to login
        text += build_response_refill('message', 'Error, login session not valid')
    else:  # a valid session so process the recording of the entry.
        matching_entries = access_database_with_result(
            "trafficdb.db",
            """SELECT COUNT(*) FROM traffic_data
            WHERE location = ? AND type = ? AND occupancy = ?
            AND username = ? AND session_id =?""",
            parameters['locationinput'][0], parameters['typeinput'][0],
            parameters['occupancyinput'][0], iuser, imagic
        )

        if matching_entries[0][0] == 0:
            text += build_response_refill('message', 'No matching entries')
        else:
            matching_entries = access_database_with_result(
                "trafficdb.db",
                """SELECT COUNT(*) FROM traffic_data
                WHERE location = ? and type = ? and occupancy = ?
                and username = ? and session_id =? AND undo_flag = 0""",
                parameters['locationinput'][0], parameters['typeinput'][0],
                parameters['occupancyinput'][0], iuser, imagic
            )

            if matching_entries[0][0] == 0:
                text += build_response_refill('message', 'Entry already removed')
            else:
                row_to_change = access_database_with_result(
                    "trafficdb.db",
                    """SELECT MAX(rowid) FROM traffic_data
                    WHERE location = ? and type = ? and occupancy = ? and username = ?
                    and session_id =? AND undo_flag=0""",
                    parameters['locationinput'][0], parameters['typeinput'][0],
                    parameters['occupancyinput'][0], iuser, imagic)[0][0]

                access_database("trafficdb.db",
                                """UPDATE traffic_data SET undo_flag=1 WHERE rowid = ?;""",
                                row_to_change)

                text += build_response_refill('message', 'Entry removed')

    count = str(access_database_with_result("trafficdb.db",
                                            """SELECT COUNT(*) FROM traffic_data
                                            WHERE undo_flag = 0 AND session_id = ?""",
                                            imagic)[0][0])

    text += build_response_refill('total', count)

    text += "</response>\n"
    user = ''
    magic = ''
    return [user, magic, text]


# This code handles the selection of the back button on the record form (page.html)
# You will only need to modify this code if you make changes elsewhere that break its behaviour
def handle_back_request(iuser, imagic, parameters):
    text = "<response>\n"
    if handle_validate(iuser, imagic) is not True:
        text += build_response_redirect('/index.html')
    else:
        text += build_response_redirect('/summary.html')
    text += "</response>\n"
    user = ''
    magic = ''
    return [user, magic, text]


# This code handles the selection of the logout button on the summary page (summary.html)
# You will need to ensure the end of the session is recorded in the database
# And that the session magic is revoked.
def handle_logout_request(iuser, imagic, parameters):
    access_database("trafficdb.db",
                    """UPDATE sessions set end_time = datetime('now','localtime')
                    where username = ? and session_id = ?""", iuser, imagic)

    text = "<response>\n"
    text += build_response_redirect('/index.html')
    user = '!'
    magic = ''
    text += "</response>\n"
    return [user, magic, text]


# This code handles a request for update to the session summary values.
# You will need to extract this information from the database.
def handle_summary_request(iuser, imagic, parameters):
    """Provides the summary statistics for the current session"""
    text = "<response>\n"
    if handle_validate(iuser, imagic) is not True:
        text += build_response_redirect('/index.html')
    else:
        text += build_response_refill('sum_car', '0')
        text += build_response_refill('sum_taxi', '0')
        text += build_response_refill('sum_bus', '0')
        text += build_response_refill('sum_motorbike', '0')
        text += build_response_refill('sum_bicycle', '0')
        text += build_response_refill('sum_van', '0')
        text += build_response_refill('sum_truck', '0')
        text += build_response_refill('sum_other', '0')
        text += build_response_refill('total', '0')

        totals = dict(access_database_with_result("trafficdb.db",
                                                  """SELECT type, count(type) FROM traffic_data
                                                  where undo_flag = 0 and session_id = ? and username = ?
                                                  group by type""", imagic, iuser))
        total_num = sum(totals.values())
        for k, v in totals.items():
            text += build_response_refill('sum_' + k, str(v))

        text += build_response_refill('total', str(total_num))

        text += "</response>\n"
        user = ''
        magic = ''
    return [user, magic, text]


# HTTPRequestHandler class
class myHTTPServer_RequestHandler(BaseHTTPRequestHandler):

    # GET This function responds to GET requests to the web server.
    def do_GET(self):

        # The set_cookies function adds/updates two cookies returned with a webpage.
        # These identify the user who is logged in. The first parameter identifies the user
        # and the second should be used to verify the login session.
        def set_cookies(x, user, magic):
            ucookie = Cookie.SimpleCookie()
            ucookie['u_cookie'] = user
            x.send_header("Set-Cookie", ucookie.output(header='', sep=''))
            mcookie = Cookie.SimpleCookie()
            mcookie['m_cookie'] = magic
            x.send_header("Set-Cookie", mcookie.output(header='', sep=''))

        # The get_cookies function returns the values of the user and magic cookies if they exist
        # it returns empty strings if they do not.
        def get_cookies(source):
            rcookies = Cookie.SimpleCookie(source.headers.get('Cookie'))
            user = ''
            magic = ''
            for keyc, valuec in rcookies.items():
                if keyc == 'u_cookie':
                    user = valuec.value
                if keyc == 'm_cookie':
                    magic = valuec.value
            return [user, magic]

        # Fetch the cookies that arrived with the GET request
        # The identify the user session.
        user_magic = get_cookies(self)

        print(user_magic)

        # Parse the GET request to identify the file requested and the GET parameters
        parsed_path = urllib.parse.urlparse(self.path)

        # Decided what to do based on the file requested.

        # Return a CSS (Cascading Style Sheet) file.
        # These tell the web client how the page should appear.
        if self.path.startswith('/css'):
            self.send_response(200)
            self.send_header('Content-type', 'text/css')
            self.end_headers()
            with open('.'+self.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # Return a Javascript file.
        # These tell contain code that the web client can execute.
        if self.path.startswith('/js'):
            self.send_response(200)
            self.send_header('Content-type', 'text/js')
            self.end_headers()
            with open('.'+self.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # A special case of '/' means return the index.html (homepage)
        # of a website
        elif parsed_path.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('./index.html', 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # Return html pages.
        elif parsed_path.path.endswith('.html'):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('.'+parsed_path.path, 'rb') as file:
                self.wfile.write(file.read())
            file.close()

        # The special file 'action' is not a real file, it indicates an action
        # we wish the server to execute.
        elif parsed_path.path == '/action':
            self.send_response(200)  # respond that this is a valid page request
            # extract the parameters from the GET request.
            # These are passed to the handlers.
            parameters = urllib.parse.parse_qs(parsed_path.query)

            if 'command' in parameters:
                # check if one of the parameters was 'command'
                # If it is, identify which command and call the appropriate handler function.
                if parameters['command'][0] == 'login':
                    print(user_magic)
                    [user, magic, text] = handle_login_request(
                        user_magic[0], user_magic[1], parameters)
                    # The result to a login attempt will be to set
                    # the cookies to identify the session.
                    if user == '!':
                        set_cookies(self, '', '')
                    else:
                        set_cookies(self, user, magic)
                elif parameters['command'][0] == 'add':
                    [user, magic, text] = handle_add_request(
                        user_magic[0], user_magic[1], parameters)
                    if user == '!':  # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'undo':
                    [user, magic, text] = handle_undo_request(
                        user_magic[0], user_magic[1], parameters)
                    if user == '!':  # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'back':
                    [user, magic, text] = handle_back_request(
                        user_magic[0], user_magic[1], parameters)
                    if user == '!':  # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'summary':
                    [user, magic, text] = handle_summary_request(
                        user_magic[0], user_magic[1], parameters)
                    if user == '!':  # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                elif parameters['command'][0] == 'logout':
                    [user, magic, text] = handle_logout_request(
                        user_magic[0], user_magic[1], parameters)
                    if user == '!':  # Check if we've been tasked with discarding the cookies.
                        set_cookies(self, '', '')
                else:
                    # The command was not recognised, report that to the user.
                    text = "<response>\n"
                    text += build_response_refill('message',
                                                  'Internal Error: Command not recognised.')
                    text += "</response>\n"

            else:
                # There was no command present, report that to the user.
                text = "<response>\n"
                text += build_response_refill('message', 'Internal Error: Command not found.')
                text += "</response>\n"
            self.send_header('Content-type', 'application/xml')
            self.end_headers()
            self.wfile.write(bytes(text, 'utf-8'))
        else:
            # A file that does n't fit one of the patterns above was requested.
            self.send_response(404)
            self.end_headers()
        return


# This is the entry point function to this code.
def run():
    print('starting server...')
    # You can add any extra start up code here
    # Server settings
    # Choose port 8081 over port 80, which is normally used for a http server
    server_address = ('127.0.0.1', 8081)
    httpd = HTTPServer(server_address, myHTTPServer_RequestHandler)
    print('running server...')
    httpd.serve_forever()  # This function will not return till the server is aborted.


run()
