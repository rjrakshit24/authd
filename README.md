# Authenticated Service

This project was a part of a submission to the cybersecurity course CY6740 Network Security. The goal of the project was to develop a password-authenticated network service with defenses against denial-of-service attacks and online password guessing attacks (bruteforce attacks).

## Service Specification

The service implements a simple protocol using [protobuf v3](https://developers.google.com/protocol-buffers) messages. In this protocol, each message is preceded by a two-byte, big-endian integer giving the length of the following protobuf message. Each TCP connection only supports one message exchange. The protocol is as shown below.

```
Client → Server : u16(|Request|)⋅Request
Server → Client : u16(|Response|)⋅Response
```

The messages themselves are defined as follows.

```proto
syntax = "proto3";

message Request {
    oneof request {
        StopRequest stop = 1;
        ResetBlockListsRequest reset = 2;
        ExpressionRequest expr = 3;
    }
}

message StopRequest {}
message ResetBlockListsRequest {}

message ExpressionRequest {
    string username = 1;
    string password = 2;
    string expression = 3;
}

message Response {
    oneof response {
        StopResponse stop = 1;
        ResetBlockListsResponse reset = 2;
        ExpressionResponse expr = 3;
    }
}

message StopResponse {}
message ResetBlockListsResponse {}

message ExpressionResponse {
    bool authenticated = 1;
    string result = 2;
}
```

- The protocol runs on port `1300/tcp`. 
- `StopRequest` is a meta-request intended; upon reception, the server must immediately terminate. 
- `ResetBlockListsRequest` is also a meta-request; upon reception, the server must immediately expunge all block list entries.
- Server implements user authentication by checking usernames and passwords against a provided database. The database will consist of a TOML document that contains an array of user objects with `username` and `password_hash` keys. Password hashes follow PHC string format with following hash algorithms -- SHA-256, SHA-512, bcrypt, Argon2.
  
  An example user database is as follows:

    ```toml
    [[users]]
    username = "mario"
    password_hash = "$argon2id$v=19$m=65536,t=3,p=1$g/CeU8p5733PmVOq9R6DkA$QB+aA9ry4vZMhgmCDdWWBc4Bo8SDTSwLV+H8UUSoGO4"

    [[users]]
    username = "luigi"
    password_hash = "$5$rounds=535000$KXabkqjRS9WfMw2V$MEBaT9Hcbdvcg4f9s7LGCR.lUE2u8OeslxVlsaXZD29"
    ```

- On successful authentication, the `authenticated` field is set to true in the response. The server provide the result of evaluation of the python expression contained in the request’s `expression` field in the response’s `result` field. 
- If authentication failed, `authenticated` must be set to false in the response and `result` is undefined.
- Expression evaluation is implemented by executing a Python interpreter on the expression. The result is the captured output of the evaluation (stdout only).

## Defenses against Attacks

The service implements defenses against denial-of-service and password guessing attacks.

1. The server provide concurrent service for multiple clients but does not exceed several resource limits -- 256 MB of memory usage, 8 processes/threads.

2. The server identifies clients that send 3 or more invalid requests within the span of 30 seconds to the service, and permanently block those source IP addresses. 
  
    *Note: (Invalid requests are those that fail to parse, that do not contain a required field such as a username or password, that contain an invalid password, that contain an invalid expression, or have any other feature that prevents a successful response.)*

3. The server identifies and terminate expression evaluations that take longer than 5 seconds to compute. Users that submit such expressions are permanently blocked.

4. The server time out slow clients to avoid Slowloris style attacks. Slow clients are defined as those that take more than 10 seconds to send a request. Source IP addresses for offending clients must be permanently blocked.

## Build and Run

To build and run this project, you need [docker installed](https://docs.docker.com/engine/install/) on your machine.

Once docker is installed, clone the repository, and follow these steps:

1. Build the docker image - `docker build --pull --rm -f "authd/Dockerfile" -t <image_name>:latest "authd"`
2. Run the docker image - `docker run -it --rm -p 1300:1300 -v <host_path>/users.toml:/tmp/users.toml <image_name> /tmp/users.toml`