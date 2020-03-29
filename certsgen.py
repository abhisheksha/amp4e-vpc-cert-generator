# AMP for Endpoints VPC Certificate Generation Utility
# Abhishek Sha
# No support is provided for running this script.

import random
from OpenSSL import crypto, SSL
from os.path import exists, join

print("This tool will help you generate the certificates in a quick fashion which are required for the various services of the AMP VPC.")
input("Are you ready?")


fqdn = []
country = input("Enter the country:")
state = input("Enter the state:")
org = input("Enter your organisation name:")
ou = input("Enter the deptarment or OU name:")
ca_fqdn = input("Enter the FQDN of your CA:")
fqdn.append(input("Enter the FQDN of authentication service:"))
fqdn.append(input("Enter the FQDN of console:"))
fqdn.append(input("Enter the FQDN of disposition server:"))
fqdn.append(input("Enter the FQDN of disposition extended protocol service:"))
fqdn.append(input("Enter the FQDN of disposition update service:"))
fqdn.append(input("Enter the FQDN of FMC integration service:"))

#Creating a key pair for the CA
ca_public_key = crypto.PKey()
ca_public_key.generate_key(crypto.TYPE_RSA, 2048)

#create a self signed cert for the CA
ca = crypto.X509()
ca.get_subject().C = country
ca.get_subject().ST = state
ca.get_subject().O = org
ca.get_subject().OU = ou
ca.get_subject().CN = ca_fqdn
ca.get_serial_number()
ca.gmtime_adj_notBefore(0)
ca.gmtime_adj_notAfter(20*365*24*60*60)
ca.set_issuer(ca.get_subject())
ca.set_pubkey(ca_public_key)
ca.sign(ca_public_key, 'sha256')


def services_cert_generator(received_fqdn):
    services_key = crypto.PKey()
    services_key.generate_key(crypto.TYPE_RSA, 2048)
    services_cert = crypto.X509()
    services_cert.get_subject().C = country
    services_cert.get_subject().ST = state
    services_cert.get_subject().O = org
    services_cert.get_subject().OU = ou
    services_cert.get_subject().CN = received_fqdn
    services_cert.get_serial_number()
    services_cert.gmtime_adj_notBefore(0)
    services_cert.gmtime_adj_notAfter(20*365*24*60*60)
    services_cert.set_issuer(ca.get_subject())
    services_cert.set_pubkey(services_key)
    services_cert.sign(ca_public_key, 'sha256')
    return services_cert,services_key

open("capublickey.pem", "wb").write(crypto.dump_certificate(crypto.FILETYPE_PEM,ca))
open("caprivatekey.key", "wb").write(crypto.dump_privatekey(crypto.FILETYPE_PEM,ca_public_key))

i = 0
while i < len(fqdn):
    services_cert,services_key = services_cert_generator(fqdn[i])
    pem = fqdn[i] + ".pem"
    key = fqdn[i] + ".key"
    open(pem, "wb").write(crypto.dump_certificate(crypto.FILETYPE_PEM,services_cert))
    open(key, "wb").write(crypto.dump_privatekey(crypto.FILETYPE_PEM,services_key))
    print("The certificate has been generated for {}".format(fqdn[i]))
    i += 1