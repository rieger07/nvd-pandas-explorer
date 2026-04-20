# nvd pandas explorer

This is a barebones python script to explore nvdcve-2.0-2025 + nvdcve-2.0-2026 as of 04/19/2026

You can run main.py with the included vulns.pq

Or you can download the json zips from https://nvd.nist.gov/vuln/data-feeds#:~:text=Feed-,Updated,that%20apply%20to%20their%20products.

## Getting Started

Requires any relatively recent python (3.6+)

`python -m venv venv`

`source venv/bin/activate`

`pip install -r requirements.txt`

`python main.py`

If you would like to add additional information from the nvd cve fields it is relatively straightforward in the python code.

If you download more recent json files, put them in the json folder, and delete/move the vulns.pq and the script will regenerate the .pq file on next `python main.py`