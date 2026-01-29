# Bad ASN Checker
A python script for checking the reputation of an IP address's ISP/owner.  It will retrieve an IP address's ASN (Autonomous System Number), then checks it against lists of ASN with a poor reputation.  The results will be output to the terminal.

## List being used/checked
The following lists below are what is checked:
- [brianhama list](https://github.com/brianhama/bad-asn-list/blob/master/bad-asn-list.csv)
- [Spamhaus list](https://www.spamhaus.org/drop/asndrop.json)
- [nullifiedcode list](https://www.spamhaus.org/drop/asndrop.json)

## Requirements:
`bad_asn_check.py` uses python3 along with a couple libraries (listed in requirements.txt) that will be installed in the installation section.

## Installation:
### Linux:
Follow each step below to install the script. 
```
cd ~
git clone https://github.com/haircutfish/bad_asn_check.git
sudo chmod 755 ~/bad_asn_check/dc.py
python3 -m pip install --user -r ~/bad_asn_check/requirements.txt
sudo ln -sf ~/bad_asn_check/bad_asn_check.py /usr/local/bin/bad_asn_check.py
```
### Windows:
Download the file as a zip:
- https://github.com/haircutfish/bad_asn_check/archive/refs/heads/main.zip

Unzip the file, then follow the steps below:
```
python3 -m pip install --user -r ~/bad_asn_check/requirements.txt
```
## Usage:
In the terminal, type the following command:
```
bad_asn_check.py -i IP_ADDRESS
```
## Example:
```
bad_asn_check.py -i 185.199.110.153
```
## Output:
```
      =================================
      ||    ***Bad ASN Checker***    ||
      =================================
ASN Name            : AS54113 Fastly, Inc.
brianhama List      : Not on List
Spamhaus List       : Not on List
NullifiedCode List  : Not on List
```
