import json
import paho.mqtt.client as mqtt
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import CertificateSigningRequestBuilder, NameOID
from cryptography.hazmat.primitives import hashes
from datetime import datetime

# Générer une paire de clés pour le client
def generate_client_key_pair():
    vendeur_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    vendeur_public_key = vendeur_private_key.public_key()
    with open("vendeur_private_key.pem", "wb") as f:
        f.write(vendeur_private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))
    with open("vendeur_public_key.pem", "wb") as f:
        f.write(vendeur_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
    return vendeur_private_key, vendeur_public_key

vendeur_private_key, vendeur_public_key = generate_client_key_pair()

# Créer une demande de signature de certificat (CSR)
def create_csr(client_private_key, common_name):
    csr = CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"), x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Client Organization"), x509.NameAttribute(NameOID.COMMON_NAME, common_name)])).sign(client_private_key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')

csr = create_csr(vendeur_private_key, u"vendeur.example.com")

# Callback pour la connexion MQTT
def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))
    client.subscribe("vehicle")
    client.publish("vehicle", json.dumps({"action": "issue", "csr": csr}))

# Callback pour la réception des messages MQTT
def on_message(client, userdata, msg):
    message = json.loads(msg.payload)
    certificate = message.get("certificate")
    if certificate:
        with open("vendeur_certificate.pem", "w") as f:
            f.write(certificate)
        print("Certificate received and saved as vendeur_certificate.pem")

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message
client.connect("194.57.103.203", 1883, 60)
client.loop_forever()
