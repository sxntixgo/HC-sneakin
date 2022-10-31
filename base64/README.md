# Challenge

Arg!! How do you still manage to get in!!?? Nevermind, I've learned from my mistakes and your previous attacks won't work this time. I came across this techique that is going to be the **base** of my authentication mechanisms. 

> Note: This challenge has been designed so that you can solve it without brute forcing the web app or using a dictionary attack on the password field.

Here's the web app:

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