from websocket_server import WebsocketServer
import threading

# Define what we do when a new client connects
def new_client(client, server):
    print("New client connected and was given id %d" % client['id'])
    server.send_message_to_all("Hey all, a new client has joined us")

# Define what we do when a client sends a message
def message_received(client, server, message):
    print("Client(%d) said: %s" % (client['id'], message))
    server.send_message(client, "I received your message: " + message)

# Define what we do when a client disconnects
def client_left(client, server):
    print("Client(%d) disconnected" % client['id'])

# Create a Websocket Server on localhost:8080
server = WebsocketServer(port=8080, host='127.0.0.1')

# Set the functions to be called on certain events
server.set_fn_new_client(new_client)
server.set_fn_message_received(message_received)
server.set_fn_client_left(client_left)

# Start the server forever on a separate thread
thread = threading.Thread(target=server.run_forever)
thread.start()
