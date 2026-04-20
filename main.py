import json
import os
import pandas as pd
import logging

logging.basicConfig(level=logging.DEBUG)
LOGGER = logging.getLogger()


def load_files(folder):
    vulnerabilities = list()
    for root, _, files in os.walk(folder):
        for _file in files:
            if ".json" not in _file:
                continue
            file_path = os.path.join(root, _file)
            with open(file_path, "r", encoding="utf-8") as f:
                temp = json.load(f)
                vulnerabilities.extend(temp["vulnerabilities"])
    return vulnerabilities


def fresh():
    # Load a specific year's data
    cve_items = load_files("json")

    # Extract CVE items
    # cve_items = data.get("vulnerabilities", [])

    # Process into a flat list
    processed_data = []
    for item in cve_items:
        cve = item["cve"]
        # ID
        cve_id = cve["id"]

        # Description
        description = [x["value"] for x in cve["descriptions"] if x["lang"] == "en"][0]

        # Weaknesses
        weaknesses = set()
        if "weaknesses" in cve:
            for w in cve["weaknesses"]:
                for d in w["description"]:
                    if d["lang"] == "en":
                        weaknesses.add(d["value"])

        # Vendors
        current_vendors = set()
        if "configurations" in cve:
            configs = cve["configurations"]
            for c in configs:
                for n in c["nodes"]:
                    for m in n["cpeMatch"]:
                        #      0..:1..:2:3...........:...etc
                        # e.g. cpe:2.3:a:itsourcecode:school_management_system:1.0:*:*:*:*:*:*:*
                        current_vendors.add(m["criteria"].split(":")[3])

        processed_data.append(
            {
                "CVE_ID": cve_id,
                "Description": description,
                "Weaknesses": weaknesses,
                "Vendors": current_vendors,
            }
        )

    df = pd.DataFrame(processed_data)
    df.to_parquet("vulns.pq")


if __name__ == "__main__":
    if os.path.exists("vulns.pq"):
        df = pd.read_parquet("vulns.pq")
        print(df.head())
        cwe_79 = df[df["Weaknesses"].apply(lambda x: "CWE-79" in x)]
        LOGGER.info(
            "Generating the top 10 vendors reporting vulnerabilities related to CWE-79 in 2026"
        )
        vendor_counts = cwe_79.explode("Vendors")["Vendors"].value_counts()
        print(vendor_counts.head(10))

        cwe_22 = df[df["Weaknesses"].apply(lambda x: "CWE-22" in x)]
        LOGGER.info(
            "Generating the top 10 vendors reporting vulnerabilities related to CWE-22 in 2026"
        )
        vendor_counts = cwe_22.explode("Vendors")["Vendors"].value_counts()
        print(vendor_counts.head(10))

    else:
        fresh()
