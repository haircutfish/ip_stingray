<p align="center">
  <img src="assets/IP_stingray_logo.png" alt="IP Stingray Logo" width="300"/>
</p>

# IP Stingray
Formally know as bad_asn_checker.  It's a Python script for checking the reputation of an IP address's ISP/owner. It will retrieve an IP address's ASN (Autonomous System Number) and intelligence data, then checks the ASN against lists with a poor reputation. The results will be output to the terminal.

## Resources being used/checked
The following resources are used to gather intelligence and check for malicious activity:
- [ipapi.is](https://ipapi.is/) (for IP Intelligence & ASN retrieval)
      - ipapi has a free tier that allows for up to 1,000 requests a day.  If you plan on making more than that, please sign up for an API key at https://ipapi.is/.
- [brianhama list](https://github.com/brianhama/bad-asn-list/blob/master/bad-asn-list.csv)
- [Spamhaus list](https://www.spamhaus.org/drop/asndrop.json)
- [nullifiedcode list](https://raw.githubusercontent.com/NullifiedCode/ASN-Lists/refs/heads/main/all.txt)

## Requirements:
`ip_stingray` uses Python 3 along with a couple of libraries (listed in `requirements.txt`) that will be installed in the installation section.

## Installation:

### Windows:
To install the tool globally so it can be run from anywhere, open PowerShell or Command Prompt, navigate to the project directory, and run:
```powershell
cd path\to\ip_stingray
pip install .
```
*(Note: If you encounter an error saying the command is not recognized when running the tool, you may need to add your Python `Scripts` folder to your Windows Environment `PATH`.)*

### Linux:
To install the tool globally, open your terminal, navigate to the project directory, and run:
```bash
cd /path/to/ip_stingray
pip3 install .
```
*(Note: Depending on your system configuration, you might want to use a virtual environment or add `--user` if pip restricts global installation).*

## Usage:

### Setting up the API Key (Optional)
If you plan to make more than 1,000 requests per day, you must set an API key from [ipapi.is](https://ipapi.is/).
Save your API key securely to your system by running:
```bash
ip_stingray --set-api-key YOUR_API_KEY
```
*(Alternatively, you can set the `IPAPI_KEY` environment variable).*

### Standard Lookups
If you installed the script globally and it is correctly added to your system's PATH, use the following command from anywhere:
```bash
ip_stingray -i IP_ADDRESS
```

Alternatively, if you did not add it to your PATH, you can run the wrapper script directly from the project directory:
```bash
python run.py -i IP_ADDRESS
```

## Example:
```bash
ip_stingray -i 8.8.8.8
```

## Output:
```text
      =================================
      ||      ***IP Stingray***     ||
      =================================

----------- IP Intelligence ------------
ASN                 : AS15169 Google LLC
Location            : Mountain View, California, United States
Datacenter          : Yes
Proxy               : No
VPN                 : No
Abuser              : Yes
Company Abuse Score : 0.0039 (Low)
ASN Abuse Score     : 0.0009 (Low)

---------- Threat List Checks ----------
Brian Hama List     : Considered Malicious
Spamhaus List       : Not on List
NullifiedCode List  : Considered Malicious

-------------- Evaluation --------------
Overall Threat Score: High Risk
```

## Troubleshooting

### "Command Not Found" Error after Installation
If you successfully ran `pip install -e .` but receive a "command not found" (or "not recognized") error when trying to run `ip_stingray`, it means your Python scripts directory is not in your system's Environment `PATH`.

**Windows Resolution:**
1. Press the Windows key, search for **Environment Variables**, and select "Edit the system environment variables".
2. Click the **Environment Variables...** button.
3. Under the "User variables" section, select **Path** and click **Edit...**.
4. Click **New** and add the path to your Python Scripts folder (typically `C:\Users\YOUR_USERNAME\AppData\Local\Programs\Python\Python3X\Scripts` or `C:\Users\YOUR_USERNAME\AppData\Roaming\Python\Python3X\Scripts`).
5. Click OK on all windows and **restart your terminal**.

**Linux / macOS Resolution:**
1. Open your shell configuration file (e.g., `~/.bashrc`, `~/.zshrc`, or `~/.profile`).
2. Add the following line to the end of the file to include the Python user bin directory:
   ```bash
   export PATH="$HOME/.local/bin:$PATH"
   ```
3. Save the file and reload your shell configuration by running `source ~/.bashrc` (or the respective file), or simply restart your terminal.
