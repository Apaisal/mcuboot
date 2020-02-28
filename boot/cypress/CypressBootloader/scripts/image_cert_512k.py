"""
Copyright (c) 2019 Cypress Semiconductor Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

"""
Script to generate JWT certificate for Cypress Bootloader
"""
import os
import json
import hashlib
from datetime import datetime
import click
from jwcrypto import jwk, jwt
from intelhex import IntelHex

IMAGE_ID = 0
CERT_EXP = datetime(2019, 12, 31)

NUMBER_OF_ITEMS_IN_VER = 4

def validate_version(ctx, param, version_string):
    """
    Returns input string if it has a valid format.
    Otherwise raises ValueError exception.
    """

    _ = ctx
    _ = param

    if version_string is None:
        version_string = '0.0.0.0'

    version_list = version_string.split('.')

    try:
        if len(version_list) != NUMBER_OF_ITEMS_IN_VER:
            raise ValueError('Version string must be in format MAJOR.MINOR.REVISION.BUILD')

        for item in version_list:
            int(item)

    except ValueError as error:
        raise click.BadParameter("{}".format(error))

    return version_string

def process_image(image, version):
    """
    Read image address and size and calculate image hash
    """
    ih = IntelHex(image)
    ih.padding = 0x00

    image_addr = ih.minaddr()
    image_size = ih.maxaddr() - ih.minaddr() + 1

    sha256 = hashlib.sha256()
    sha256.update(ih.tobinarray(start=image_addr, size=image_size))

    image_hash = sha256.digest()

    image_attr = {}
    image_attr['image_hash'] = image_hash
    image_attr['image_addr'] = image_addr
    image_attr['image_size'] = image_size
    image_attr['image_id'] = IMAGE_ID
    image_attr['version'] = version

    return image_attr

def load_key(key):
    """
    Load JWK for certificate signing
    """
    key_str = key.read()
    key_json = json.loads(key_str)
    return key_json

def create_cert_payload(image, image_attr, key, exp):
    """
    Create payload for the image certificate
    """
    # Remove private part from JWK
    key_pub = key['cy_pub_key']

    payload = {}
    payload["image_id"] = image_attr['image_id']
    payload["image_hash"] = list(image_attr['image_hash'])
    payload["image_file"] = os.path.basename(image)
    payload["image_address"] = image_attr['image_addr']
    payload["image_size"] = image_attr['image_size']
    payload["image_version"] = image_attr['version']
    payload["policy_template"] = ""
    payload["cy_pub_key"] = key_pub
    payload["iat"] = int(datetime.now().timestamp())
    payload["exp"] = int(exp.timestamp())

    return payload

def create_certificate(payload, key, output):
    """
    Create JWT certificate
    """
    key_priv = key['cy_priv_key']
    token = jwt.JWT(header={"alg": "ES256"}, claims=payload)
    token.make_signed_token(jwk.JWK(**key_priv))
    token_str = token.serialize(compact=True)
    output.write(token_str)

@click.command()
@click.option('-i', '--image', 'image',
              type=click.Path(),
              default=None,
              help='Image in the Intel HEX format.')
@click.option('-k', '--key', 'key',
              type=click.File('r'),
              default=None,
              help='Private key in the JWK format to sign certificate.')
@click.option('-o', '--cert', 'img_cert',
              type=click.File('w'),
              default='out.jwt',
              help='Certificate for input image in the JWT format.')
@click.option('-v', '--version', callback=validate_version)
def main(image, key, img_cert, version):
    """
    Entry point of the script
    """
    image_attr = process_image(image, version)
    key_json = load_key(key)
    payload = create_cert_payload(image, image_attr, key_json, CERT_EXP)
    create_certificate(payload, key_json, img_cert)
    print('Image certificate was created successfully. Image version {}.'.format(version))

if __name__ == "__main__":
    main(None, None, None, None)
