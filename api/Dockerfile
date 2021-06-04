FROM golang:alpine as build-env
WORKDIR /src
COPY go.sum go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLE=0 go build -o /bin/app .
RUN ls /bin

FROM alpine
COPY --from=build-env /bin/app /bin/app
COPY .env /etc/smugglerenv
ENTRYPOINT ./bin/app --config=/etc/smugglerenv
