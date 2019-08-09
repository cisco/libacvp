## ACVP Metadata

ACVP specification defines sections related to the creation and management of Operating Environment "metadata".
This metadata is used when the client requests that a testSession be submitted for a FIPS validation.
Some of this metadata must be pre-existing, i.e. it must have been created before requesting a validation.
This directory contains a tool called `metadata.py` which is a python program that can be used to help aid the
creation of 2 specific types of metadata, "Vendors" and "Persons".

This directory also contains a file named `validation.json` which is an example of a properly formatted file
which must be fed into Libacvp when attempting to perform a FIPS validation. That file in particular specifies
metadata which will be fed into the library to become available for usage in the validation operation.

#### Creating Metadata

As previously mentioned, there is a helper Python program within this directory named `metadata.py`.
This program has 2 primary purposes:

1. Create a new "Vendor" or "Person".
2. Querying the status of a "request" (the state a resource is in prior to being "approved").

When the program is used with the "--metadata-file" option, the user must supply a valid JSON file which
contains a list of "vendors" or "persons" or both. While the program scans the file, it will first
check to see if any of the "vendors" or "persons" are already existing within the server database.
If any are found to be pre-existing, the program will display the information and continue to any
other entries within the file. Otherwise the program will submit the "vendor" or "person" data to the
server, at which point the submission will eventually be manually approved or declined.
This manual step of approving or declining is unfortunately out of our hands, and the best
we can do is either poll the status and wait, or check again later.

It's important to keep in mind that a "vendor" is a dependency of a "person" (via "vendorUrl").
This means that a "person" cannot be created without the attached "vendor" already existing
and available within the server database. Thus the program will not be able to submit a "person"
until the attached "vendor" is approved.

The following subsection goes over the format requirements for a "--metadata-file".

##### --metadata-file format

At the top level, everything is contained within a JSON object.
Within the top-level object, there can be either a list named "vendors" or a list named "persons.

###### vendors

This list can contain 1 or many objects.
Each object must follow the following format:

* "id"
    * Used for program tracking purposes
    * Type: positive integer
    * MUST be unique

* "name"
    * Type: String
    * Required

* "website"
    * Type: String
    * Optional

* "emails"
    * Type: List of strings
    * Optional

* "phoneNumbers"
    * Type: List of objects where each object MUST contain:
        * "number"
        * "type"
    * The value for "number" and "type" MUST be of type string.
    * Optional

* "addresses"
    * Type: List of objects where each object MAY contain:
        * "street1"
        * "street2"
        * "street3"
        * "locality"
        * "region"
        * "country"
        * "postalCode"
    * The value for all of the above MUST be of type string.
    * Optional

#### Libacvp FIPS Validation
The example validation.json file shows how the library expects the data to be formatted in order
for it to be successfully loaded for usage.
This subsection will go over some of the format requirements and how it can be tweaked to achieve different results.

###### vendors
As it is currently implemented, the library requires that there is at least 1 object in the "vendors" array.
Additionally, this data must already be existing in the server database because it cannot be created inline
during the validation operation. The data must be an exact match, and if there are any duplicates in the database
the library will try to use the FIRST exact match that is found.

* "id" is used for library tracking purposes. It must be a positive integer, and it must be unique.

* "name" is required. "website", "emails", and "phoneNumbers" are optional.

* The "address" object is required. It must have at least 1 of: "street1", "street2", "street3", "locality",
"region", "country", "postalCode".

* The "contacts" array is required, and it must contain at least 1 object.
    * Each object in the "contacts" array is required to have "fullName". The "emails" and "phoneNumbers" are optional.

###### modules
The user can either choose to provide the "modules" data via the JSON file,
or via the library API during program runtime. This data can be created on-the-spot (not required to be pre-existing).

* "id" is used for library tracking purposes. It must be a positive integer, and it must be unique.

* "vendorId" is used for library tracking puposes only. It must be a valid vendor ID.
  This is the vendorUrl that will appear in the module data during the FIPS validation.

* "name" is required. At least 1 of "version", "type", "description" is required.

###### operating\_environments
The user can either choose to provide the operating environments data via the JSON file,
or via the library API during program runtime. This data can be created on-the-spot (not required to be pre-existing).

* "id" is used for library tracking purposes. It must be a positive integer, and it must be unique.

* "name" is required.

* "dependencies" array is required and must have at least 1 object.
    * Each object in the "dependencies" array is required to have at least 1 of "type", "name", "description".
    * The user is expected to provide valid key/value combinations according to the ACVP apecification (beyond scope of this doc).

