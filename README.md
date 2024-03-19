# flask-google-login
Register and Login with Google OAuth using Flask and SQLite


## Install requirements

```shell
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
---
<br>

> In google developer console create a project and 
credentials

<br>

---

## Setup `.env` variables
Create a `.env`add these variables and their respective values :

- `APP_SECRET_KEY=` YOUR CLIENT SECRET
- `GOOGLE_CLIENT_ID=` YOUR GOOGLE_CLIENT_ID

## Download Client Secret
- Download your `client secret` json file and rename it to `client_secret.json` and place it in the root folder of this app


## Create SQLite database
- Run 
```
python create_db.py
```

 to create your the sqlite databse `users.sqlite3` which will store the users on registration automatically.


## Add `/callback` URIs to Authorized URIs in google developer console

- The app runs on `http://localhost:3000`
- I use two different routes for login and registration
- In you `Authorized URIs` section add these following two URIs 
   
   - ```
     http://localhost:300/callback
     ```
   - ```
     http://localhost:3000/login/callback
     ```
    
    and click `SAVE`  

## Start
```
$ python app.py
```
Open : 
```
http://localhost:3000
```

## Working 

- Seperate flows for registration and login

- On registration, the user's google username, password and the oauthId which is unique per user is stored in the database and redirected to home

- On login, the process takes flow and checks the email that is used for login is already in the database and creates a session redirecting to home where you can see a welcome message and logout link, or it will simply redirect to home


## Reference

- flask-google-login : https://github.com/pj8912/flask-google-login
- How to Create Google OAuth2 client_secret.json file : https://www.youtube.com/watch?v=kr_OYm3ZmUI

- https://jakpentest.tistory.com/341