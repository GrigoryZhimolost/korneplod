# What is this
This library is for transfering encrypted data through TCP/IP, just for this. It uses ml-kem and ChaCha20 to encrypt data, so you don't have to worry about your data's safety.

# Features
* data's encrypted with ChaCha20
* key and nonce exchange is proceeded with ml-kem in 1024-bit mode
* it's completely asynchronous

Some features(e.g. refusing/accepting connections based on channels) will be added in further versions.

# How to use this
Here are basic usage examples below:

server
``` rust
use korneplod::server::Server;
use korneplod::tools::sockaddr_from;
use korneplod::Message;
//Binding server
let mut server = Server::new( sockaddr_from("127.0.0.1", 1448, false).unwrap() ).await?;

//listening and handshaking an incoming connection
let mut client = server.listen_handshaked(true, Some([78u8; 32])).await.unwrap();

//Creating a message to send
let message = Message::new("new message".as_bytes().to_vec(), 0);

//Sending the message
client.send_message(&message).await?;
```

client
``` rust
use korneplod::client::Client;
use korneplod::tools::sockaddr_from;

//Connecting to listener
let mut client = Client::connect( sockaddr_from("127.0.0.1", 1448, false).unwrap() ).await?;

//Performing handshaking
client.handshake(Some([78u8; 32])).await?;

//Getting a message
let message = client.get_message().await?;

assert_eq!(String::from_utf8(message.get_content_vec()).unwrap(), "new message");
```