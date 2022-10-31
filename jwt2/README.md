# Challenge

That was definitely a fluke! I have not changed the authentication mechanism, but I have fixed my mitake. Now you won't be able to use that attack to get the API Key, but you welcome to try anyways.

> Note: This challenge has been designed so that you can solve it without brute forcing the web app or using a dictionary attack on the password field.

>Note: Solving this challenge along with "Jason Webb Telescope, Stage 1" will unlock three additional challenges in the same category.

Here is the URL: 

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