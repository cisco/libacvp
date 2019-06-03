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


def compare_emails(this, their):
    if "emails" in this:
        if this["emails"] != their["emails"]:
            # The emails string lists are not equal
            return False
    else:
        if len(their["emails"]) != 0:
            # The candidate has a non-empty "emails" list, but our vendor does not
            return False
    return True


def compare_phone_numbers(this, their):
    if "phoneNumbers" in this:
        if this["phoneNumbers"] != their["phoneNumbers"]:
            # The list of phoneNumber dicts are not equal
            return False
    else:
        if len(their["phoneNumbers"]) != 0:
            # The candidate has a non-empty "phoneNumbers" list, but our vendor does not
            return False
    return True


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

        try:
            addresses = data["addresses"]

            if type(addresses) is not list:
                raise ValueError("JSON field 'addresses' must be a list")
            for x in addresses:
                if not isinstance(x, dict):
                    raise ValueError("This item needs to be a dict")
                for key, value in x.items():
                    if key not in ["street1", "street2", "street3", "locality",
                                   "region", "country", "postalCode"]:
                        raise ValueError(f"This dict contains an unknown key({key})")
                    if not isinstance(value, str):
                        raise ValueError("This value needs to be a str")

                    if "street2" in x:
                        if x["street2"] is None:
                            # Don't include for null values
                            del x["street2"]

                    if "street3" in x:
                        if x["street3"] is None:
                            # Don't include for null values
                            del x["street3"]

            clean_data["addresses"] = addresses
        except KeyError:
            # Not required
            pass

        # This will throw away all of the fields that we didn't add above
        # in case there are any stragglers
        return clean_data

    def _match_exact(self, candidates):
        def compare_name(this, their):
            if this["name"] != their["name"]:
                return False
            return True

        def compare_website(this, their):
            if "website" in this:
                if this["website"] != their["website"]:
                    # The "website" string doesn't match
                    return False
            else:
                if their["website"] is not None:
                    # The candidate has "website" string, but our vendor doesn't
                    return False
            return True

        def compare_addresses(this, their):
            if "addresses" in this:
                if len(this["addresses"]) != len(their["addresses"]):
                    # The length of the lists are not the same
                    return False

                for this_address in this["addresses"]:
                    match = False

                    for their_address in their["addresses"]:
                        # First we remove anything from the candidate that has "null" value.
                        their_address = {key: val for key, val in their_address.items() if val is not None}
                        # Also remove the "url" field.
                        del their_address["url"]

                        if this_address == their_address:
                            # Match here!
                            match = True
                            break

                    if not match:
                        # None of the candidate addresses equal this address, so total miss.
                        return False
            else:
                if len(their["addresses"]) != 0:
                    # The candidate has a non-empty "addresses" list, but our vendor does not
                    return False
            return True

        for c in candidates:
            if not compare_name(self.data, c):
                continue
            if not compare_website(self.data, c):
                continue
            if not compare_emails(self.data, c):
                continue
            if not compare_phone_numbers(self.data, c):
                continue
            if not compare_addresses(self.data, c):
                continue

            ##
            # Go with the first match (assume no duplicates)
            ##
            self.server_data = c
            self.url = c["url"]
            self.complete = True
            return

    def _query(self, next_endpoint=None):
        params = None

        if not next_endpoint:
            # First page.
            # Need to form the query syntax
            url = f"https://{ACV_SERVER}/{ACV_API_PREFIX}/vendors"
            params = dict()

            params["name[0]"] = ":".join(["eq", self.data["name"]])

            if "website" in self.data:
                params["website[0]"] = ":".join(["eq", self.data["website"]])

            if "emails" in self.data:
                for i, email in enumerate(self.data["emails"]):
                    params[f"email[{i}]"] = ":".join(["eq", email])

            # TODO add phone number here

        else:
            # Use next_endpoint.
            # Preserved query syntax with proper offset.
            url = f"https://{ACV_SERVER}{next_endpoint}"

        r = {
            'url': url,
            'headers': HEADERS,
            'cert': CERT,
        }
        if CA_FILE:
            r['verify'] = CA_FILE
        if params:
            r['params'] = params

        response = requests.get(**r)
        resp_json = response.json()

        # Exact match here against the list of partial matches
        self._match_exact(resp_json[1]["data"])
        if self.complete is True:
            return

        if resp_json[1]["incomplete"] is True:
            # Get the next page of partial matches, and try to match again
            next_link = resp_json[1]["links"]["next"]
            self._query(next_endpoint=next_link)

    def register(self):
        # Query the server DB to see if this vendor already exists
        self._query()
        if self.complete:
            info = (
                f"--Preexisting Vendor--\n"
                f"url: {self.url}\n"
                f"Vendor: {self.data}\n"
                f"Server Resource: {self.server_data}\n"
            )
            print(info)
            return

        request = {
            'url': f"https://{ACV_SERVER}/{ACV_API_PREFIX}/vendors",
            'json': self.to_send,
            'headers': HEADERS,
            'cert': CERT
        }
        if CA_FILE:
            request['verify'] = CA_FILE

        response = requests.post(**request)

        # The URL given by server to check the "request" details
        self.status_url = response.json()[1]["url"]
        get_request_status(self)

        if not self.complete:
            info = (
                f"--Initial/Processing--\n"
                f"requestUrl: {self.status_url}\n"
                f"vendor: {self.data}\n"
            )
            print(info)


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
                # The JSON value is null
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

    def _match_exact(self, candidates):
        def compare_full_name(this, their):
            if this["fullName"] != their["fullName"]:
                return False
            return True

        for c in candidates:
            if not compare_full_name(self.data, c):
                continue
            if not compare_emails(self.data, c):
                continue
            if not compare_phone_numbers(self.data, c):
                continue

            ##
            # Go with the first match (assume no duplicates)
            ##
            self.server_data = c
            self.url = c["url"]
            self.complete = True
            return

    def _query(self, next_endpoint=None):
        params = None

        if not next_endpoint:
            # First page.
            # Need to form the query syntax
            url = f"https://{ACV_SERVER}/{ACV_API_PREFIX}/persons"
            params = dict()

            # Full name
            params["fullName[0]"] = ":".join(["eq", self.data["fullName"]])

            # Vendor ID. Split the url string and get last element.
            vendor_id = self.vendor_url.split("/")[-1]
            params["vendorId[0]"] = ":".join(["eq", vendor_id])

            if "emails" in self.data:
                for i, email in enumerate(self.data["emails"]):
                    params[f"email[{i}]"] = ":".join(["eq", email])
        else:
            # Use next_endpoint.
            # Preserved query syntax with proper offset.
            url = f"https://{ACV_SERVER}{next_endpoint}"

        r = {
            'url': url,
            'headers': HEADERS,
            'cert': CERT,
        }
        if CA_FILE:
            r['verify'] = CA_FILE
        if params:
            r['params'] = params

        response = requests.get(**r)
        resp_json = response.json()

        # Exact match here against the list of partial matches
        self._match_exact(resp_json[1]["data"])
        if self.complete is True:
            return

        if resp_json[1]["incomplete"] is True:
            # Get the next page of partial matches, and try to match again
            next_link = resp_json[1]["links"]["next"]
            self._query(next_endpoint=next_link)

    def _verify(self, vendors):
        ##
        # First we get the vendorUrl that this Person is linked with
        ##
        if self.vendor_url:
            # Make a new Resource (representing Vendor) for querying the URL
            r = Resource()
            r.url = self.vendor_url

            # If the Vendor exists, this will succeed.
            # Otherwise, an HTTP exception will be raised.
            r.server_data = get_resource_server_data(r)

        elif self.vendor_id:
            vendor = None
            for v in vendors:
                if v.id == self.vendor_id:
                    vendor = v
                    break

            if not vendor:
                raise ValueError(f"vendor_id({self.vendor_id}) does not match any from 'vendors' JSON")

            if vendor.url:
                # This Vendor should already have been verified as existing by this point
                self.vendor_url = vendor.url
                self.data["vendorUrl"] = self.vendor_url
            else:
                raise ValueError("Linked Vendor does not have approved URL")

        else:
            raise ValueError("Need either vendor_url or vendor_id")

        ##
        # Now query the server to see if the Person has already been registered.
        ##
        self._query()

    def register(self, vendors):
        # Check linked vendor, and query to see if Person already exists
        self._verify(vendors)
        if self.complete:
            info = (
                f"--Preexisting Person--\n"
                f"url: {self.url}\n"
                f"Person: {self.data}\n"
                f"Server Resource: {self.server_data}\n"
            )
            print(info)
            return

        request = {
            'url': f"https://{ACV_SERVER}/{ACV_API_PREFIX}/persons",
            'json': self.to_send,
            'headers': HEADERS,
            'cert': CERT
        }
        if CA_FILE:
            request['verify'] = CA_FILE

        response = requests.post(**request)

        # The URL given by server to check the "request" details
        self.status_url = response.json()[1]["url"]
        get_request_status(self)

        if not self.complete:
            info = (
                f"--Initial/Processing--\n"
                f"requestUrl: {self.status_url}\n"
                f"Person: {self.data}\n"
            )
            print(info)


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


def register_vendors(vendors):
    complete = True
    total = len(vendors)
    remaining = total

    if total == 0:
        # No vendors to register
        return

    # Go through and register each Vendor
    for v in vendors:
        v.register()

        if v.complete:
            remaining -= 1
        else:
            complete = False

    print(f"Vendors {total-remaining}/{total} complete.\n")

    ##
    # This will loop forever unless one of these conditions is met:
    # 1. All of the statuses from the Server are "complete"
    # 2. ctrl-c interrupt from console
    ##
    try:
        while not complete:
            # Wait 60 seconds
            time.sleep(60)

            # Reset here, because this time everything might be done
            complete = True
            show_progress = False

            for v in vendors:
                if v.complete:
                    # This one is finished.
                    continue

                # Ask the server what the request status is
                get_request_status(v)
                if v.complete:
                    remaining -= 1
                    show_progress = True
                else:
                    complete = False

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
        p.register(vendors)
        if p.complete:
            remaining -= 1
        else:
            complete = False

    print(f"Persons {total-remaining}/{total} complete.\n")

    ##
    # This will loop forever unless one of these conditions is met:
    # 1. All of the statuses from the Server are "complete"
    # 2. ctrl-c interrupt from console
    ##
    try:
        while not complete:
            # Wait 60 seconds
            time.sleep(60)

            # Reset here, because this time everything might be done
            complete = True
            show_progress = False

            for p in persons:
                if p.complete:
                    # This one is finished.
                    continue

                # Ask the server what the request status is
                get_request_status(p)
                if p.complete:
                    remaining -= 1
                    show_progress = True
                else:
                    complete = False

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
