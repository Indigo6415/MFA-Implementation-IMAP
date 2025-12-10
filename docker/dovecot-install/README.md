# Installation
1) Start docker container `docker-compose up -d --build`
2) Spin up http server using `python3 -m http.server 8080`

# Usage
1) Start authentication test using `doveadm auth test "user@example.com" "testpassword"`
2) See a request come in on http server `GET /?username=user@example.com&password=testpassword HTTP/1.1" 200`
3) Response in docker terminal = `passdb: user@example.com auth succeeded`