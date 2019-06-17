## ACVP Metadata

ACVP specification defines sections related to the creation and management of Operating Environment "metadata".
This metadata is used when the client requests that a testSession be submitted for a FIPS validation.
Some of this metadata must be pre-existing, i.e. it must have been created before requesting a validation.
This directory contains a tool called `metadata.py` which is a python program that can be used to help aid the
creation of 2 specific types of metadata, "Vendors" and "Persons".

This directory also contains a file named `validation.json` which is an example of a properly formatted file
which must be fed into Libacvp when attempting to perform a FIPS validation. That file in particular specifies
metadata which will be fed into the library to become available for usage in the validation operation.

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

