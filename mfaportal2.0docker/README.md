# MFA Implementation:step-by-step guide

## 1.Building the container

Either build the container through the `docker-compose.yml` or build it using:
```
docker-compose build --no-cache
docker-compose up -d
```

## 2.Setup user

in the docker container: `adduser [name]`, and create a password.

## 3.MFA on the website

```
1. go to localhost:8080 in the browser (preferably incognito to avoid session/cookie errors)
2. Fill in your username and password create at the previous step (2.Setup user)
3a. If MFA isn't already initialized for your user: scan the QR-code and enter the 6-digit number for the authenticator app.
3b. Enter the 6-digit number for the authenticator app
4. You now have your own one-time app password for usage in Thunderbird.
```

## 4.Setup Thunderbird

You want to manually fill in the fields:
```
incoming server:
Servername: localhost
port: 143, security: none
authentication method: password, user: [name] (from Step 2!)
```
```
Outgoing server:
Servername: localhost
port:25, security: none
authentication method: password, user: [name] (from Step 2!)
```

## 5.Thunderbird connection test

Thunderbird should now be prompt you to fill in the password.
You need to fill in the `one-time app password` aquired at step 3. (check on the bottom left if Thunderbird proceeds after sending the credentials)

You can check if the setup is completed by sending a mail from the server:
`echo "Testmail" | mail -s "Test" [name]@localhost`


##This is the end of the guide..
