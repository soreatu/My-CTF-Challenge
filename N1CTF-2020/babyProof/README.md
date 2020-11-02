## Name

Crypto/babyProof

## Flag

n1ctf{S0me_kn0wl3dg3_is_leak3d}

## Description

An easy non-interactive zero-knowledge proof.

nc xxx.xxx.xxx.xxx 23333

## Difficulty

medium

## Build

```shell
$ cd ./env
$ docker build . -t n1ctf-crypto-babyproof
$ docker run --name babyproof -d -p 23333:23333 n1ctf-crypto-babyproof
```



