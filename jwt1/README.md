# Challenge

Alright, alright, alright... I see what you are capable of. Clearly the previous authentication mechanism was not working, so I got rid of it and moved to *signed tokens*. Good luck getting my user's API key!

> Note: This challenge has been designed so that you can solve it without brute forcing the web app or using a dictionary attack on the password field. 

>Note: Solving this challenge along with "Jason Webb Telescope, Stage 2" will unlock three additional challenges in the same category.

If you want to give it a try, here's the newest web app:

http://127.0.0.1:8090

# Docker

## Run docker

```
docker compose up --build
```

The web application will run in http://127.0.0.1:8090

## Remove docker containers

```
docker container prune
```