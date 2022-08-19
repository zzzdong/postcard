Postcard, a proxy tool over HTTP/2.
=============

## Summary

`client` will listen as socks5 proxy, then forward data to `server`.

The `client` communicate to `server` with `HTTP/2` which over encrypted stream -- `Snowstorm`.



```shell
# gen keys
cargo run --bin key-gen

# run client
cargo run --bin pc-client -- --host 0.0.0.0:1089 --server 127.0.0.1:8080 --private-key ${private_key} --public-key ${public_key}

# run server
cargo run --bin pc-server -- --host 0.0.0.0:8080 --private-key ${private_key} --public-key ${public_key}
```
