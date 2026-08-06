FROM golang:1.26-alpine

WORKDIR /app

RUN apk add --no-cache postgresql-client git

RUN go install github.com/cosmtrek/air@v1.49.0 && \
    go install github.com/google/wire/cmd/wire@latest

COPY go.mod ./
RUN touch go.sum

COPY . .

COPY .air.toml ./

CMD ["air", "-c", ".air.toml"]