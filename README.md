# OpenCTI Cortex Analyzer

[OpenCTI](https://www.opencti.io/en/) is an open cyber threat intelligence platform which aims at providing a powerful knowledge management database with an enforced schema especially tailored for cyber threat intelligence and cyber operations and based on STIX 2.
![octi-dashboard_fs_bg-02072024](https://github.com/user-attachments/assets/120cc906-4fd5-4261-a1f6-6cfd89e240ac)

[Cortex](https://github.com/thehive-project/Cortex/) solves two common problems frequently encountered by SOCs, CSIRTs and security researchers in the course of threat intelligence, digital forensics and incident response:

    - How to analyze observables they have collected, at scale, by querying a single tool instead of several?
    - How to actively respond to threats and interact with the constituency and other teams?

## Flavors

The analyzer comes in two flavors to search for an observable in the platform:

- **OpenCTI_SearchExactObservable**: Returns an exact match of the input data from OpenCTI.
- **OpenCTI_SearchObservables**: Returns all observables containing the input data.

## Supported Data Types
`domain`, `ip`, `url`, `fqdn`, `uri_path`, `user-agent`, `hash`, `mail`, `mail_subject`, `registry`, `regexp`, `other`, `filename`, `mail-subject`

## Requirements & Configuration

The OpenCTI analyzer requires you to have access to one or several OpenCTI instances. 

The following parameters must be configured in Cortex for the analyzer to work (in the `OpenCTI` configuration section):

- **`name`** (List of Strings): Name(s) of the OpenCTI server(s).
- **`url`** (List of Strings): URL(s) of the OpenCTI server(s).
- **`key`** (List of Strings): API key(s) (token) for the OpenCTI server(s).
- **`cert_check`** (Boolean): Verify server certificate (default: `true`).

*Note: If querying multiple instances simultaneously, ensure that the `name`, `url`, and `key` lists contain the same number of elements in the corresponding order.*

## How to Run

### 1. In Cortex (Using Docker)
This analyzer is natively packaged as a Docker image and properly configured in `analyzers.json`. You can import this analyzer into Cortex and run it using the Docker executor. 

Example configuration in `application.conf` (or via Cortex UI):
```hocon
analyzer {
  # analyzer location
  # url needs to point at location where analyzers.json is stored
  urls = [
    "https://catalogs.download.strangebee.com/latest/json/analyzers.json"
    #"/absolute/path/of/analyzers.json" 
  ]
  ...
}
```

### 2. Manual / Local Testing

To test the analyzer locally without Cortex, you can feed a Cortex JSON job representation to `opencti.py` via `stdin`.

**Method A: Python environment**
1. Install Python requirements:
   ```bash
   pip3 install -r requirements.txt
   ```
2. Run a query:
   ```bash
   echo '{
     "data": "1.1.1.1",
     "dataType": "ip",
     "config": {
       "name": ["Demo"],
       "url": ["https://demo.opencti.io"],
       "key": ["YOUR_API_KEY"],
       "cert_check": true,
       "service": "search_exact"
     }
   }' | python3 opencti.py
   ```

**Method B: Docker**
You can run the analyzer manually within its Docker container:
```bash
docker build -t opencti-analyzer .
echo '{...}' | docker run -i --rm opencti-analyzer
```
*(Replace `{...}` with the JSON payload shown in Method A)*

