


```bash

mkdir tls

cd tls
# gen tls stuff
git clone https://github.com/michaelklishin/tls-gen.git




# fix server_key.pem

openssl rsa -in tls/server_key.pem --out tls/server_key.pem



```