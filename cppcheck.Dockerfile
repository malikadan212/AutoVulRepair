FROM alpine:latest
RUN apk add --no-cache cppcheck
ENTRYPOINT ["cppcheck"]
