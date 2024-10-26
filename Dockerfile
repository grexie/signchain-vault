FROM golang:alpine AS build

WORKDIR /app

COPY . /app

RUN go build -o /vault . 

FROM alpine:latest

COPY --from=build /vault /vault

CMD ["/vault"]