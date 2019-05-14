#!/usr/bin/env python3
"""
* Copyright (c) 2019, Cisco Systems, Inc.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://github.com/cisco/libacvp/LICENSE
*
"""

import os
import time
import requests
import json
import argparse
import pyotp
import hashlib
import base64

ACVP_VERSION = "1.0"
ACV_API_PREFIX = "acvp/v1"

try:
    ACV_SERVER = os.environ['ACV_SERVER']
except KeyError as e:
    raise type(e)(str(e) + ' ... Need to "export ACV_SERVER"')

ACV_CERT_FILE = os.environ.get('ACV_CERT_FILE')
ACV_KEY_FILE = os.environ.get('ACV_KEY_FILE')
if ACV_CERT_FILE and ACV_KEY_FILE:
    CERT = (ACV_CERT_FILE, ACV_KEY_FILE)
else:
    CERT = None

CA_FILE = os.environ.get('ACV_CA_FILE')

TOTP_SEED = os.environ.get('ACV_TOTP_SEED')
ACCESS_TOKEN = None  # JWT
HEADERS = None


class Resource:
    def __init__(self, data=None):
        self.url = None
        self.status_url = None
        self.error_msg = None
        self.complete = False
        self.data = data
        self.server_data = None
        self.to_send = [{"acvVersion": ACVP_VERSION}, data]


class Vendor(Resource):
    def __init__(self, data):
        super().__init__(self._ingest_data(data))

    def _ingest_data(self, data):
        self.id = data["id"]

        clean_data = dict()
        clean_data["name"] = data["name"]

        try:
            clean_data["website"] = data["website"]
        except KeyError:
            # Not required
            pass

        try:
            emails = data["emails"]

            if type(emails) is not list:
                raise ValueError("JSON field 'emails' must be a list")
            if not all(isinstance(x, str) for x in emails):
                raise ValueError("This item needs to be a str")

            clean_data["emails"] = emails
        except KeyError:
            # Not required
            pass

        try:
            addresses = data["addresses"]

            if type(addresses) is not list:
                raise ValueError("JSON field 'addresses' must be a list")
            for x in addresses:
                if not isinstance(x, dict):
                    raise ValueError("This item needs to be a dict")
                for key, value in x.items():
                    if key not in ["street1", "locality", "region", "country", "postalCode"]:
                        raise ValueError(f"This dict contains an unknown key({key})")
                    if not isinstance(value, str):
                        raise ValueError("This value needs to be a str")

            clean_data["addresses"] = addresses
        except KeyError:
            # Not required
            pass

        # This will throw away all of the fields that we didn't add above
        # in case there are any stragglers
        return clean_data


class Person(Resource):
    def __init__(self, data):
        self.vendor_id = None
        self.vendor_url = None
        super().__init__(self._ingest_data(data))

    def _ingest_data(self, data):
        clean_data = dict()
        clean_data["fullName"] = data["fullName"]

        try:
            # The url was provided, so use that as priority
            vendor_url = data["vendorUrl"]
            if vendor_url is None:
                raise ValueError

            clean_data["vendorUrl"] = vendor_url
            self.vendor_url = vendor_url
        except (KeyError, ValueError):
            # Secondary fallback to the user designated vendor ID
            self.vendor_id = data["vendorId"]

        try:
            emails = data["emails"]

            if type(emails) is not list:
                raise ValueError("JSON field 'emails' must be a list")
            if not all(isinstance(x, str) for x in emails):
                raise ValueError("This item needs to be a str")

            clean_data["emails"] = emails
        except KeyError:
            # Not required
            pass

        try:
            phone_numbers = data["phoneNumbers"]

            if type(phone_numbers) is not list:
                raise ValueError("JSON field 'phoneNumbers' must be a list")
            for x in phone_numbers:
                if not isinstance(x, dict):
                    raise ValueError("This item needs to be a dict")
                for key, value in x.items():
                    if key not in ["number", "type"]:
                        raise ValueError(f"This dict contains an unknown key({key})")
                    if not isinstance(value, str):
                        raise ValueError("This value needs to be a str")

            clean_data["phoneNumbers"] = phone_numbers
        except KeyError:
            # Not required
            pass

        # This will throw away all of the fields that we didn't add above
        # in case there are any stragglers
        return clean_data


def print_resource_details(resource):
    if resource.error_msg:
        deets = (
            f"--Failure--\n"
            f"requestUrl: {resource.status_url}\n"
            f"User provided Resource: {resource.data}\n"
            f"errorMessage: {resource.error_msg}\n"
        )
    else:
        deets = (
            f"--Success--\n"
            f"approvedUrl: {resource.url}\n"
            f"requestUrl: {resource.status_url}\n"
            f"Server Resource: {resource.server_data}\n"
        )

    print(deets)


def check_server_error(j, code):
    error = j["error"]

    if code == 401:
        # Unauthorized
        if error.startswith("JWT expired"):
            # Need to refresh the JWT
            login(refresh=True)
            return

    raise requests.exceptions.HTTPError(f"Unhandled HTTP Error... code {code}")


def get_resource_server_data(resource, stop=False):
    if not resource.url:
        return None

    url = f"https://{ACV_SERVER}{resource.url}"
    request = {
        'url': url,
        'headers': HEADERS,
        'cert': CERT
    }
    if CA_FILE:
        request['verify'] = CA_FILE

    response = requests.get(**request)

    if response.ok:
        return response.json()[1]
    else:
        if not stop:
            check_server_error(response.json(), response.status_code)
            # Try one more time
            return get_resource_server_data(resource, stop=True)
        else:
            raise requests.exceptions.HTTPError(f"Hard Stop with HTTP Error... code {response.status_code}")


def get_request_status(resource, stop=False):
    url = f"https://{ACV_SERVER}{resource.status_url}"
    request = {
        'url': url,
        'headers': HEADERS,
        'cert': CERT
    }
    if CA_FILE:
        request['verify'] = CA_FILE

    response = requests.get(**request)

    if response.ok:
        status = response.json()[1]["status"]

        if status in ["initial", "processing"]:
            pass
        elif status == "approved":
            resource.complete = True
            resource.url = response.json()[1]["approvedUrl"]
            resource.server_data = get_resource_server_data(resource)
            print_resource_details(resource)
        elif status == "rejected":
            resource.complete = True
            resource.error_msg = response.json()[1]["message"]
            print_resource_details(resource)
        else:
            raise ValueError(f"Invalid server 'status': {status}\n")
    else:
        if not stop:
            check_server_error(response.json(), response.status_code)
            # Try one more time
            get_request_status(resource, stop=True)
        else:
            raise requests.exceptions.HTTPError(f"Hard Stop with HTTP Error... code {response.status_code}")


def verify_person_linked_vendor(person, vendors):
    if person.vendor_url:
        # Make a new Resource (representing Vendor) for querying the URL
        r = Resource()
        r.url = person.vendor_url

        # If the Vendor exists, this will succeed.
        # Otherwise, an HTTP exception will be raised.
        r.server_data = get_resource_server_data(r)

    elif person.vendor_id:
        vendor = None
        for v in vendors:
            if v.id == person.vendor_id:
                vendor = v
                break

        if not vendor:
            raise ValueError(f"vendor_id({person.vendor_id}) does not match any from 'vendors' JSON")

        # TODO query the server DB to make sure the vendor exists
        if vendor.url:
            person.vendor_url = vendor.url
            person.data["vendorUrl"] = person.vendor_url
        else:
            raise ValueError("Linked Vendor does not have approved URL")

    else:
        raise ValueError("Need either vendor_url or vendor_id")


def send_vendor(vendor):
    request = {
        'url': f"https://{ACV_SERVER}/{ACV_API_PREFIX}/vendors",
        'json': vendor.to_send,
        'headers': HEADERS,
        'cert': CERT
    }
    if CA_FILE:
        request['verify'] = CA_FILE

    response = requests.post(**request)

    # The URL given by server to check the "request" details
    vendor.status_url = response.json()[1]["url"]
    get_request_status(vendor)


def send_person(person):
    request = {
        'url': f"https://{ACV_SERVER}/{ACV_API_PREFIX}/persons",
        'json': person.to_send,
        'headers': HEADERS,
        'cert': CERT
    }
    if CA_FILE:
        request['verify'] = CA_FILE

    response = requests.post(**request)

    # The URL given by server to check the "request" details
    person.status_url = response.json()[1]["url"]
    get_request_status(person)


def register_vendors(vendors):
    complete = True
    total = len(vendors)
    remaining = total

    if total == 0:
        # No vendors to register
        return

    # Go through and register each Vendor
    for v in vendors:
        send_vendor(v)
        if not v.complete:
            complete = False
            deets = (
                f"--Initial/Processing--\n"
                f"requestUrl: {v.status_url}\n"
                f"vendor: {v.data}\n"
            )
            print(deets)
        else:
            remaining -= 1

    print(f"Vendors {total-remaining}/{total} complete.\n")

    ##
    # This will loop forever unless one of these conditions is met:
    # 1. All of the statuses from the Server are "complete"
    # 2. ctrl-c interrupt from console
    ##
    try:
        while not complete:
            # Wait 30 seconds
            time.sleep(30)

            # Reset here, because this time everything might be done
            complete = True
            show_progress = False

            for v in vendors:
                if v.complete:
                    # This one is finished.
                    continue

                # Ask the server what the request status is
                get_request_status(v)
                if not v.complete:
                    complete = False
                else:
                    remaining -= 1
                    show_progress = True

            if show_progress:
                print(f"Vendors {total - remaining}/{total} complete.\n")
    except KeyboardInterrupt:
        pass


def register_persons(persons, vendors):
    complete = True
    total = len(persons)
    remaining = total

    if total == 0:
        # No persons to register
        return

    # Go through and register each Person
    for p in persons:
        # Make sure the linked vendor is valid
        verify_person_linked_vendor(p, vendors)

        # Submit this Person
        send_person(p)
        if not p.complete:
            complete = False
            deets = (
                f"--Initial/Processing--\n"
                f"requestUrl: {p.status_url}\n"
                f"vendor: {p.data}\n"
            )
            print(deets)
        else:
            remaining -= 1

    print(f"Persons {total-remaining}/{total} complete.\n")

    ##
    # This will loop forever unless one of these conditions is met:
    # 1. All of the statuses from the Server are "complete"
    # 2. ctrl-c interrupt from console
    ##
    try:
        while not complete:
            # Wait 30 seconds
            time.sleep(30)

            # Reset here, because this time everything might be done
            complete = True
            show_progress = False

            for p in persons:
                if p.complete:
                    # This one is finished.
                    continue

                # Ask the server what the request status is
                get_request_status(p)
                if not p.complete:
                    complete = False
                else:
                    remaining -= 1
                    show_progress = True

            if show_progress:
                print(f"Persons {total - remaining}/{total} complete.\n")
    except KeyboardInterrupt:
        pass


def load_vendors(j):
    vendors = []
    taken_ids = []
    for vendor in j["vendors"]:
        vid = vendor["id"]
        if vid in taken_ids:
            # We have already ingested a Vendor with this same id value
            raise ValueError(f"Vendor id({vid}) already used by previous Vendor. Unique id required for each Vendor.")
        else:
            # Don't allow duplicates
            taken_ids.append(vid)

        v = Vendor(vendor)
        vendors.append(v)

    return vendors


def load_persons(j):
    persons = []
    for person in j["persons"]:
        p = Person(person)
        persons.append(p)

    return persons


def create_resources(metadata_file=None):
    if not metadata_file:
        return

    with open(metadata_file) as f:
        metadata_json = json.load(f)

    # Create a list of Vendor from the JSON
    vendors = load_vendors(metadata_json)
    # Register the list of Vendor with server
    register_vendors(vendors)

    # Create a list of Person from the JSON
    persons = load_persons(metadata_json)
    register_persons(persons, vendors)


def check_request_statuses(request_urls=None):
    if not request_urls:
        return

    for url in request_urls:
        r = Resource()
        r.status_url = url

        get_request_status(r)
        if not r.complete:
            deets = (
                f"--Incomplete--\n"
                f"requestUrl: {r.status_url}\n"
            )
            print(deets)


def totp():
    if not TOTP_SEED:
        return None
    seed = base64.b64decode(TOTP_SEED.encode())
    seed_b32 = base64.b32encode(seed)
    otp = pyotp.totp.TOTP(seed_b32, digits=8, digest=hashlib.sha256)
    return otp.now()


def login(refresh=False):
    global ACCESS_TOKEN, HEADERS

    if refresh:
        j = [{"acvVersion": ACVP_VERSION}, {"accessToken": ACCESS_TOKEN}]
    else:
        if TOTP_SEED:
            j = [{"acvVersion": ACVP_VERSION}, {"password": totp()}]
        else:
            j = [{"acvVersion": ACVP_VERSION}]

    request = {
        'url': f"https://{ACV_SERVER}/{ACV_API_PREFIX}/login",
        'json': j,
        'cert': CERT,
        'headers': HEADERS,
    }
    if CA_FILE:
        request['verify'] = CA_FILE

    r = requests.post(**request)

    ACCESS_TOKEN = r.json()[1]["accessToken"]

    if refresh:
        # Update the JWT
        HEADERS["Authorization"] = f"Bearer {ACCESS_TOKEN}"
    else:
        HEADERS = {
            "Authorization": f"Bearer {ACCESS_TOKEN}"
        }


def main():
    parser = argparse.ArgumentParser(
        description='Create/register new metadata resources in the NIST database.'
    )
    parser.add_argument('--metadata-file',
                        dest='metadata_file',
                        help='Absolute path to file containing the metadata which will be registered.')
    parser.add_argument('--request-status',
                        dest='request_urls',
                        nargs='+',
                        help='A list of "request" URLs that will be polled for their state.')
    args = parser.parse_args()

    if not args.metadata_file and not args.request_urls:
        raise argparse.ArgumentError('Need to provide either --metadata-file or --request-status')

    login()

    check_request_statuses(args.request_urls)

    create_resources(args.metadata_file)


if __name__ == '__main__':
    main()
