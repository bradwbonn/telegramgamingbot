import json, boto3, base64
from botocore.exceptions import ClientError
from os import getenv
from urllib3 import PoolManager

# init variables
custom_filter = [{'Name':'tag:gaming'}]
http200 = { 'statusCode': 200 }
# Initialize environment variables
masteradmin = getenv('masteradmin')
userdbname = getenv('userdbname')
secretsmanagerregion = getenv('secretsmanagerregion')
bottokenname = getenv('bottokenname')
serverdbname = getenv('serverdbname')
# Available commands and their associated help text
command_prefixes = {
        "/help": 'For help about a specific command, type /help [command]',
        "/showstatus": "Get information about a specific server.\n/showstatus <servername>",
        "/startserver": "Admins-only. Start a server up. Bear in mind, there may be several minutes before the server is fully ready for play, even after it shows as running.\n/startserver <servername>",
        "/stopserver": "Admins-only. Cleanly shut down a gaming server by name. \n/stopserver <servername>",
        "/user": 'Show information about your privileges on the bot.',
        "/showusers": 'List all users that the bot has currently authenticated',
        "/adduser": "Admins-only. Use it add a new Telegram user to the bot, or to change their privileges.\n/adduser <username> [admin|user]",
        "/deleteuser": "Admins-only. Use it to delete a Telgram username from the bot.\n/deleteuser <username>",
        "/maintenance": "{} only. Place the bot in maintenance mode so no other commands are avaialble.".format(masteradmin),
        "/showservers": "List all servers that the bot is currently managing. If yours isn't showing up, ask {} for help.".format(masteradmin)
    }

# Obtain the gaming bot's Telegram token from Secrets Manager
def get_secret():

    secret_name = bottokenname
    region_name = secretsmanagerregion

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        print('Cannot get token')
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            
    # Your code goes here. 
    return secret

# Check to see if a specific user is known and an admin
def get_user(username):
    dynamdbclient = boto3.client('dynamodb')
    response = dynamdbclient.get_item(
        TableName = userdbname,
        Key={'username': { 'S': username } }
        )
    try:
        if response['Item']['admin']['BOOL'] == True:
            return "admin"
        else:
            return "user"
    except:
        return "unknown"

# Put the user into the database
def add_user(username, usertype):
    # The master administrator is set by env variable, and cannot be changed by the bot.
    if (username == masteradmin) or (username == 'MaintenanceModeToken'):
        return False
    dynamdbclient = boto3.client('dynamodb')
    if usertype == "admin":
        adminstatus = True
    else:
        adminstatus = False
    try:
        response = dynamdbclient.put_item(
            TableName = userdbname,
            Item={
                'username': { 'S': username },
                'admin': { 'BOOL': adminstatus }
            }
        )
        return True
    except:
        return False
    
# Delete a user from the database
def delete_user(username):
    if (username == masteradmin) or (username == 'MaintenanceModeToken'):
        return False
    dynamdbclient = boto3.client('dynamodb')
    try:
        response = dynamdbclient.delete_item(
            TableName = userdbname,
            Key={
                'username': { 'S': username }
            }
        )
        return True
    except: 
        return False

# Deliver a text message to a specific chat in Telegram
def send_message(text, chat_id):
    full_secret = get_secret()
    secretvalue = full_secret.split('":"')[1]
    secretvalue = secretvalue[:-2]
    TELE_TOKEN=secretvalue
    URL = "https://api.telegram.org/bot{}/".format(TELE_TOKEN)
    url = URL + "sendMessage?text={}&parse_mode=Markdown&chat_id={}".format(text, chat_id)
    myhttp = PoolManager()
    try:
        r = myhttp.request('GET', url)
    except ClientError as e:
        print("Couldn't send message to Telegram: {}".format(e))
        raise e
    if r.status != 200:
        print("Telegram response: {} {}\n{}".format(r.status,r.headers,r.data))

# Determine if the bot is in maintenance mode or not by reading the token from the DB
def check_maint():
    dynamdbclient = boto3.client('dynamodb')
    response = dynamdbclient.get_item(
        TableName='GamingServerUsers',
        Key={'username': { 'S': 'MaintenanceModeToken' } }
        )
    try:
        if response['Item']['enabled']['BOOL'] == True:
            return True
        else:
            return False
    except:
        return "unknown"

# Switch on or off Maintenance mode for the bot
def toggle_maint(setting):
    dynamdbclient = boto3.client('dynamodb')
    response = dynamdbclient.put_item(
        TableName ='GamingServerUsers',
        Item={
            'username': { 'S': 'MaintenanceModeToken' },
            'enabled': { 'BOOL': setting }
        }
    )

# Get list of servers from DynamoDB Table and send a combined message to the chat
def get_gaming_servers(chat_id):
    serverlist = ["Server list:\n*Name:* _Game_ \\[instance ID] - region"]
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(serverdbname)
    try:
        response = table.scan()
    except:
        return False
    for i in response['Items']:
        serverlist.append("*{}:* _{}_ \\[{}] - {}".format(i['servername'],i['game'],i['instanceid'],i['region']))
    send_message("\n".join(serverlist),chat_id)
    return True
    
def get_server(servername):
    dynamdbclient = boto3.client('dynamodb')
    server = {
        'name': servername,
        'instanceid': 'unknown',
        'region': 'unknown' 
    }
    try:
        response = dynamdbclient.get_item(
            TableName = serverdbname,
            Key={'servername': { 'S': servername } }
            )
    except:
        return server
    try:
        server['instanceid'] = response['Item']['instanceid']['S']
        server['region'] = response['Item']['region']['S']
        server['notes'] = response['Item']['notes']['S']
        server['game'] = response['Item']['game']['S']
    except:
        print("Couldn't get instance data from DynamoDB record for: {}".format(servername))
        return server
    return server

def server_status(servername, chat_id):
    # print("Checking status of:{}".format(servername))
    server = get_server(servername)
    if server['region'] == 'unknown':
        print("Couldn't get server details for: {}".format(servername))
        return False
    session = boto3.Session(region_name=server['region'])
    client = session.client('ec2')
    ec2 = session.resource('ec2')
    try:
        response = client.describe_instances(InstanceIds=[server['instanceid']])
        ec2instance = ec2.Instance(server['instanceid'])
    except Exception as e:
        print ("Couldn't describe instance: {}".format(e))
        return False
    try:
        ip_address = response['Reservations'][0]['Instances'][0]['PublicIpAddress']
    except:
        ip_address = "none"
    message = "*{}* ({}) \\[_{}_] IP: {}\n{}\n{}".format(
        servername,
        response['Reservations'][0]['Instances'][0]['InstanceType'],
        response['Reservations'][0]['Instances'][0]['State']['Name'],
        ip_address,
        server['game'],
        server['notes']
    )
    send_message(message,chat_id)
    return True
    
def start_server(servername, chat_id):
    server = get_server(servername)
    if server['region'] == 'unknown':
        return False
    session = boto3.Session(region_name = server['region'])
    client = session.client('ec2')
    try:
        response = client.start_instances(
            InstanceIds=[server['instanceid']]
        )
    except:
        return False
    return True
    
def stop_server(servername, chat_id):
    server = get_server(servername)
    if server['region'] == 'unknown':
        return False
    session = boto3.Session(region_name = server['region'])
    client = session.client('ec2')
    try:
        response = client.stop_instances(
            InstanceIds=[server['instanceid']]
        )
    except:
        return False
    return True

# List all users in the database
def list_users(chat_id):
    userlist = ["*Bot users:*"]
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(userdbname)
    try:
        response = table.scan()
    except:
        return False
    for i in response['Items']:
        if i['username'] == "MaintenanceModeToken":
            continue
        if i['username'] == masteradmin:
            adminstatus = "Master Admin"
        elif i['admin']:
            adminstatus = "Admin"
        else:
            adminstatus = "User"
        userlist.append("*{}* - {}".format(i['username'],adminstatus))
    send_message("\n".join(userlist),chat_id)

# Primary function handling code
def lambda_handler(event, context):
    message = json.loads(event['body'])
    
    # Catch events that aren't authorized messages and exit without op
    try:
        command = message['message']['text']
    except:
        print("No Message")
        return http200
        
    # Get the message and user from the chat     
    try:
        chat_id = message['message']['chat']['id']
        user = message['message']['from']['username']
        print("message: {} from: {} [{}]".format(command,user,chat_id))
    except Exception as e:
        print("No message data to use")
        raise e
        return http200
        
    # Command handling logic starts here
    
    # Determine if command is coming from an authorized Telegram handle
    user_status = get_user(user)
    if user_status == "unknown":
        print("Unauthorized user: {} chatId: {}".format(user,chat_id))
        send_message("Hi {}, if you would like to use this bot, have an admin add you as a user".format(user),chat_id)
        return http200
    
    # Determine if we're in maintenance mode
    maint = check_maint()
        
    # Handle toggling maintenance mode
    if (command == "/maintenance") and (user == masteradmin):
        if maint == False:
            send_message("Enabling maintenance mode...",chat_id)
            print("INFO: {} is putting the bot in maintenance mode".format(user))
            toggle_maint(True)
        else:
            send_message("Taking bot out of maintenance mode...",chat_id)
            print("INFO: {} is taking the bot out of maintenance mode".format(user))
            toggle_maint(False)
        return http200
    elif (command == "/maintenance"):
        send_message("Only {} is allowed to control me on this level.".format(masteradmin),chat_id)
        return http200
    
    # If server is in maintenance mode and we aren't trying to change that, say so and return
    if (maint == True) and (user != masteradmin):
        send_message("Sorry, I am presently in maintenance mode. Back with you shortly. Bug {} if this continues.".format(masteradmin),chat_id)
        return http200
    
    
    # Process various operational commands below
    #
    # Show the server status
    if (command[:11] == "/showstatus"):
        commands = command.split(" ")
        if len(commands) < 2:
            send_message("/showstatus <servername>",chat_id)
            return http200
        if server_status(commands[1], chat_id):
            pass
        else:
            send_message("Unknown server: {}".format(commands[1]),chat_id)

    # Power up a server
    elif (command[:12] == "/startserver") and (user_status == "admin"):
        commands = command.split(" ")
        if len(commands) < 2:
            send_message("/startserver <servername> (names are case-sensitive)",chat_id)
            return http200
        if start_server(commands[1],chat_id):
            send_message("{} is booting up {}".format(user,commands[1]),chat_id)
            print("INFO: {} started the server".format(user))
        else:
            send_message("Couldn't boot up server '{}' Remember they are case-sensitive.".format(commands[1]),chat_id)
            print("ERROR: Couldn't start server '{}'".format(commands[1]),chat_id)
        
    # Shut down the server
    elif (command[:11] == "/stopserver") and (user_status == "admin"):
        commands = command.split(" ")
        if len(commands) < 2:
            send_message("/stopserver <servername> (server names are case-sensitive)",chat_id)
            return http200
        if stop_server(commands[1],chat_id):
            send_message("NOTICE: {} is shutting down {}".format(user,commands[1]),chat_id)
            print("INFO: {} shut down the server".format(user))
        else:
            send_message("Couldn't shut down server '{}' Remember they are case-sensitive.".format(commands[1]),chat_id)
            print("ERROR: Couldn't shut down server '{}'".format(commands[1]),chat_id)
        
    # Print the help pages
    elif (command[:5] == "/help"):
        commands = command.split(" ")
        if len(commands) > 1:
            try:
                send_message(
                    "Command: {}\n{}".format(
                        commands[1],
                        command_prefixes[commands[1]]
                    ),
                    chat_id
                )
            except:
                # Add a leading slash
                try:
                    slashcommand = "/{}".format(commands[1])
                    send_message(
                        "Command: {}\n{}".format(
                            slashcommand,
                            command_prefixes[slashcommand]
                        ),
                        chat_id
                    )
                except:
                    # send_message(
                    #     "Sorry, I don't know anything about {}. But I know @Tozier is a dingus.".format(commands[1]),
                    #     chat_id
                    # )
                    pass
        else:
            complete_help = "\n\n".join([
                "I'm a helper bot that can manage the EBC gaming server(s) for you. These gaming servers are running in {}'s personal AWS account, so please be kind and shut the server(s) you're using down when you're finished with them.  Have fun!".format(masteradmin),
                "NOTE: Right now, server names are case-sensitive when interacting with them.  You can also type /help <command> for more information about a specific command.",
                "Commands:\n{}".format(
                    '\n'.join("{!s}".format(key) for key in command_prefixes.keys())
                )
            ])
            send_message(
                complete_help,
                chat_id
            )
        
    # Show the privileges of the user messaging the bot
    elif (command[:5] == "/user"):
        if (user == masteradmin):
            send_message(
                "Hi {}! You're the Master Administrator!".format(user),
                chat_id
            )
        else:
            send_message(
                "Hi {}! You are currently registered with status: {}".format(user,user_status),
                chat_id
            )
        
    # Do something silly...
    elif (command[:8] == "/fensler"):
        send_message("Hey kid...\nI'm a computer...\nStop all the downloadin'...",chat_id)
    elif (command[:8] == "/unicorn"):
        send_message("Do not ask about the unicorns. They get enough attention as it is...the egotistical pointy equines...\nThey unionized now, can you believe it?",chat_id)
        
    # Handle adding/updating a user of the bot    
    elif (command[:8] == "/adduser") and (user_status == "admin"):
        commands = command.split(" ")
        if len(commands) < 3:
            send_message("Format:\n/adduser <username> [admin|user]",chat_id)
            return http200
        if (commands[2] == "admin") or (commands[2] == "user"):
            if add_user(commands[1],commands[2]):
                send_message("{} is now a {}. Welcome!".format(commands[1],commands[2]),chat_id)
                print("INFO: {} has added user '{}' as {}".format(user,commands[1],commands[2]))
            else:
                send_message("Sorry, something went wrong. Ask {} for help. :(".format(masteradmin),chat_id)
        
    # Handle removing a user from the database
    elif (command[:11] == "/deleteuser") and (user_status == "admin"):
        commands = command.split(" ")
        if len(commands) < 2:
            send_message("Format:\n/deleteuser <username>",chat_id)
            return http200
        if delete_user(commands[1]):
            send_message("{} has been deleted as a user. So long!".format(commands[1]),chat_id)
            print("INFO: {} has deleted user '{}'".format(user,commands[1]))
        else:
            send_message("Sorry, something went wrong. Ask {} for help. :(".format(masteradmin),chat_id)
    
    # For future...
    elif (command[:10] == "/addserver") and (user_status == "admin"):
        send_message("Not implemented yet",chat_id)
    
    # For future...
    elif (command[:11] == "/dropserver") and (user_status == "admin"):
        send_message("Not implemented yet",chat_id)
        
    # List all users authenticated on the bot
    elif (command[:10]== "/showusers") and (user_status != "unknown"):
        list_users(chat_id)
    
    # Show all servers controlled by this bot
    elif (command[:12] == "/showservers") and (user_status != "unknown"):
        get_gaming_servers(chat_id)
    
    # Handle any other messages
    else:
        # send_message("Command {} not recognized.  Also, @Tozier is a dingus.".format(command), chat_id)
        pass

    # Command handling logic ends here
    return http200

