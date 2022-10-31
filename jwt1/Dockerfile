FROM golang:1.16.4 as base
RUN mkdir /app
ADD ./src /app
WORKDIR /app
EXPOSE 8080
RUN go build -o main .
CMD ["/app/main"]