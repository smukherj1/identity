
Generating a pair of ECDSA Signing keys
```
$ openssl ecparam -name prime256v1 -genkey -noout -out ec-sign-p256-priv.pem
$ openssl ec -in ec-sign-p256-priv.pem -pubout > ec-sign-p256-pub.pem 
```