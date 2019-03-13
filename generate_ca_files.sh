#!/bin/bash
#
# Refer: https://github.com/kelseyhightower/etcd-production-setup

cd etcd-ca
curl -k -o openssl.cnf \
  https://raw.githubusercontent.com/kelseyhightower/etcd-production-setup/master/openssl.cnf
mkdir private certs newcerts crl
touch index.txt
echo '01' > serial

country="/countryName=CN"
state="/stateOrProvinceName=Beijing"
locality="/localityName=Beijing"
org="/organizationName=nihao"
orgUnit="/organizationalUnitName=world"
common="/commonName="
subj_common="$country$state$locality$org$orgUnit$common"

openssl genrsa -out private/ca.key 2048
chmod 600 private/ca.key
openssl req -config openssl.cnf -subj "${subj_common}ca" -new -x509 \
  -key private/ca.key -extensions v3_ca -out certs/ca.crt

export SAN="IP:172.28.1.1, IP:172.28.1.2, IP:172.28.1.3"
#export SAN="IP:10.0.0.2, IP:10.0.0.3, IP:10.0.0.4"
openssl req -config openssl.cnf -subj "${subj_common}etcd-server" -new -nodes \
  -keyout private/etcd-server.key -out etcd-server.csr
openssl ca -config openssl.cnf -batch -extensions etcd_server \
  -keyfile private/ca.key -cert certs/ca.crt -out certs/etcd-server.crt \
  -infiles etcd-server.csr

unset SAN
openssl req -config openssl.cnf -subj "${subj_common}etcd-client" -new -nodes \
  -keyout private/etcd-client.key -out etcd-client.csr
openssl ca -config openssl.cnf -batch -extensions etcd_client \
  -keyfile private/ca.key -cert certs/ca.crt -out certs/etcd-client.crt \
  -infiles etcd-client.csr

cp certs/ca.crt certs/etcd-server.crt certs/etcd-client.crt private/etcd-server.key private/etcd-client.key .
rm -rf private certs newcerts crl index* serial* *csr openssl.cnf
