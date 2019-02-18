## CMAC Json Test Files

### AES

#### cmac\_aes.json
This is a clean file. All of the json should be correct.

#### cmac\_aes\_1.json
The value for key:"algorithm" is wrong.

#### cmac\_aes\_2.json
The key:"direction" is missing.

#### cmac\_aes\_3.json
The value for key:"direction" is wrong.

#### cmac\_aes\_4.json
The key:"keyLen" is missing.

#### cmac\_aes\_5.json
The key:"msgLen" is missing.

#### cmac\_aes\_6.json
The value for key:"macLen" is missing.

#### cmac\_aes\_7.json
The key:"key" is missing.

#### cmac\_aes\_8.json
The key:"msg" is missing.

#### cmac\_aes\_9.json
The key:"mac" is missing.

#### cmac\_aes\_10.json
The length for key:"key" is wrong.

#### cmac\_aes\_11.json
The key:"keyLen" is missing in last tg

#### cmac\_aes\_12.json
The key:"mac" is missing in last tc

### TDES - tests the things that aren't
### shared with AES

#### cmac\_tdes.json
This is a clean file. All of the json should be correct.

#### cmac\_tdes\_1.json
The key:"keyingOption" is missing.

#### cmac\_tdes\_2.json
The key:"keyingOption" is wrong.

#### cmac\_tdes\_3.json
The key:"key1" is missing.

#### cmac\_tdes\_4.json
The key:"key2" is missing.

#### cmac\_tdes\_5.json
The key:"key3" is missing.

#### cmac\_tdes\_6.json
The value for key:"msg" is too long

#### cmac\_tdes\_7.json
The length of "key1" is wrong

#### cmac\_tdes\_8.json
The length of "key2" is wrong

#### cmac\_tdes\_9.json
The length of "key3" is wrong

#### cmac\_tdes\_10.json
The key "tgId" is missing

#### cmac\_tdes\_11.json
The key:"keyingOption" is missing in last tg

#### cmac\_tdes\_12.json
The key:"mac" is missing in last tc
