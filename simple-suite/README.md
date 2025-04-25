# Authfully Simple Suite

This is an opiniated implementation of OAuth2 using [authfully][authfully],
the parent package. Since there are external dependencies required, this is 
intentionally kept as a separate subpackage. This way the parent 
dependencies is much cleaner.

You may use this suite directly. Or you may use this as an example for 
adapting the parent package to your own implementation.


## What do we have here?

- Core functionality in this folder; and
- An [authentication / authorization server implementation][auth-server] (AS); and
- An [example resource server implementation][example-resource-server] (RS); and
- An [example client application][example-client-app].


## What does this mean?

This is a short description of common OAuth 2.0 workflow.

In the most common flow ("code grant") OAuth2 architechure, there are 4 
different actors:
- Resource Own (RO), that is the user to login
- Client Application (Client)
- Authentication / Authorization Server (AS)
- Resource Server (RS)

When a user is using the client, the client may want:
1. The identity of the RO checked; and maybe
2. The resource of the RO stored in RS<br>
   For example,
   - getting a list events that the user (RO) has joinned in an online 
   calendar / event service (RS). Or;
   - adding a new post to a social network (RS) on the user's (RO) behalf.


### How the client can get a approval from user?

The client will send the user (RO) to the authentication server (AS) for a 
login process. The user would login and then, usually, visually see what
the client is asking to do in the user's behalf. The user may authorize the
use, then sent back to the client application.

```text
┌───────────┐                                        ┌──────────┐
│                      │    (A) Wants to do something.          │                    │
│                      │ ──────────────────→ │                    │
│                      │                                        │                    │
│                      │    (B) Redirect RO (user) to AS        │                    │
│                      │        with the identity of the client │ Client Applicaiton │ ←┐
│                      │        and what it needs from AS to do │                    │   │
│                      │        the something user wants        │                    │   │
│                      │        (i.e. "scope")                  │                    │   │
│                      │ ←────────────────── │                    │   │
│                      │                                        │                    │   │
│ Resource Owner (RO)  │                                        └──────────┘   │
│     i.e. user        │                                        ┌──────────┐   │
│                      │    (C) Redirected to AS.               │                    │   │
│                      │ ──────────────────→ │                    │   │
│                      │                                        │                    │   │
│                      │    (D) Show a login form, usually      │                    │   │
│                      │        for the user to login           │                    │   │
│                      │        (i.e. authentication).          │                    │   │
│                      │ ←────────────────── │                    │   │
│                      │                                        │                    │   │
│                      │    (E) Fill in login name and          │                    │   │
│                      │        password, or do whatever it     │                    │   │
│                      │        takes to login.                 │                    │   │
│                      │ ──────────────────→ │                    │   │
│                      │                                        │                    │   │
│                      │    (F) Show another form, usually      │    Authorization   │   │
│                      │        for the user to visually        │       Server       │   │
│                      │        verify what he / she is         │        (AS)        │   │
│                      │        allowing the client application │                    │   │
│                      │        to see or do.                   │                    │   │
│                      │        (i.e. authorization)            │                    │   │
│                      │ ←────────────────── │                    │   │
│                      │                                        │                    │   │
│                      │    (G) User submit the form to         │                    │   │
│                      │        verify he / she allows that.    │                    │   │
│                      │ ──────────────────→ │                    │   │
│                      │                                        │                    │   │
│                      │    (H) Redirect the user back          │                    │   │
│                      │        to the client application       │                    │   │
│                      │        with an approval "code" for     │                    │   │
│                      │        it to redeem a real token.      │                    │   │
│                      │ ──────────────────→ │                    │   │
│                      │                                        └──────────┘   │
│                      │    (I) Redirected back with the                                   │
│                      │        approval "code"                                            │
│                      │ ─────────────────────────────────┘ 
└───────────┘
```


### How the client may use the approval to get a long term access to resource?

The client applicaiton will then do a back stage roundtrip to the
authentication server

```text
┌───────────┐                                        ┌──────────┐
│                      │    (J) Using the approval "code"       │                    │
│                      │        with the client's own id and    │                    │
│                      │        password to apply for an        │                    │
│                      │        "access token" at AS.           │                    │
│                      │ ──────────────────→ │                    │
│                      │                                        │                    │
│                      │    (K) Validate both the client's      │   Authorization    │
│                      │        identity (id, password)         │       Server       │
│                      │        and the approval "code".        │        (AS)        │
│                      │        Then generate "access token"    │                    │
│                      │        of the "scope" specified by     │                    │
│                      │        client in (B).                  │                    │
│                      │ ←────────────────── │                    │
│                      │                                        │                    │
│  Client Applicaiton  │                                        └──────────┘
│                      │                                        ┌──────────┐
│                      │    (L) With the "access token",        │                    │
│                      │        ask the Resource Server (RS)    │                    │
│                      │        for resources.                  │      Resource      │
│                      │ ──────────────────→ │       Server       │
│                      │                                        │        (RS)        │
│                      │    (M) Return the resource.            │                    │
│                      │ ←────────────────── │                    │
│                      │                                        │                    │
└───────────┘                                        └──────────┘
```

### Further Readings

For more detailed description of OAuth 2.0, please see the specification website:

- https://oauth.net/2/

[authfully]: https://github.com/authfully/authfully
[auth-server]: cmd/auth-server
[example-resource-server]: cmd/example-resource-server
[example-client-app]: cmd/example-client-app/