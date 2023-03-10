import json
import csv
import os
import shutil
import requests
import sys

iqapi = 'api/v2'

iqurl = sys.argv[1]
iquser = sys.argv[2]
iqpwd = sys.argv[3]

quarantined_datadir = "./quarantined_data"
debug = False


def getNexusIqData(end_point):
    url = "{}/{}/{}" . format(iqurl, iqapi, end_point)

    req = requests.get(url, auth=(iquser, iqpwd), verify=False)

    if req.status_code == 200:
        res = req.json()
    else:
        res = "Error fetching data"

    return res


def getCVE2(reasons):
    values = []
    f = ""

    for reason in reasons:
        reference = reason["reference"]

        if not reference is None:
            newValue = reference["value"]
            if not itemExists(newValue, values):
                values.append(newValue)

    for v in values:
        f = f.join(v + ":")

    f = f[:-1]

    return f


def itemExists(item,items):
    exists = False

    for i in items:
        if i == item:
            exists = True
            break

    return exists


def init_report():

    if os.path.exists(quarantined_datadir):
        shutil.rmtree(quarantined_datadir)

    os.mkdir(quarantined_datadir)

    return


def print_jsonfile(json_data, jsonfile):
    output_file = "{}/{}{}".format(quarantined_datadir, jsonfile, ".json")
    json_formatted = json.dumps(json_data, indent=2)
    #print(json_formatted)

    with open(output_file, 'w') as outfile:
        json.dump(json_data, outfile, indent=2)

    print(output_file)
    return


def list_report(report_name, end_point):
    page = 1
    page_size = 250
    page_count, results = page_query(end_point, page, page_size, report_name)
    csvfile = "{}/{}{}".format(quarantined_datadir, report_name, ".csv")

    if page_count > 0:
        print(csvfile)

        with open(csvfile, 'w') as fd:
            writer = csv.writer(fd, delimiter=",")

            line = []
            line.append("repository")
            line.append("quarantine_date")
            line.append("date_cleared")
            line.append("path_name")
            line.append("format")
            line.append("quarantined")
            line.append("policy_name")
            line.append("threat_level")
            line.append("cve")
            writer.writerow(line)

        while page <= page_count:

            if len(results) > 0:
                print_list_report(results, csvfile)

                if debug:
                    print_jsonfile(results, report_name + "_" + str(page))

            page += 1
            page_count,results = page_query(end_point, page, page_size, report_name)

    else:
        print(csvfile + " [no data]")

    return


def page_query(end_point, page, page_size, report_name):
    asc = True

    if report_name == "autoreleased_from_quarantine_components":
        sort_by = "releaseQuarantineTime"
    else:
        sort_by = "quarantineTime"

    query = "{}?page={}&pageSize={}&sortBy={}&asc={}".format(end_point, page, page_size, sort_by, asc)
    data = getNexusIqData(query)

    page_count = data["pageCount"]
    results = data["results"]

    return (page_count,results)


def print_list_report(results, csvfile):

    with open(csvfile, 'a') as fd:
        writer = csv.writer(fd, delimiter=",")

        for result in results:
            repository = result["repository"]
            quarantine_date = result["quarantineDate"]
            date_cleared = result["dateCleared"]
            path_name = result["pathname"]
            quarantined = result["quarantined"]
            format = result["componentIdentifier"]["format"]

            if result["quarantinePolicyViolations"]:
                for quarantinePolicyViolation in result["quarantinePolicyViolations"]:
                    policy_name = quarantinePolicyViolation["policyName"]
                    threat_level = quarantinePolicyViolation["threatLevel"]

                    for constraint in quarantinePolicyViolation["constraintViolations"]:
                        cve = getCVE2(constraint["reasons"])

                        line = []
                        line.append(repository)
                        line.append(quarantine_date)
                        line.append(date_cleared)
                        line.append(path_name)
                        line.append(format)
                        line.append(quarantined)
                        line.append(policy_name)
                        line.append(threat_level)
                        line.append(cve)
                        writer.writerow(line)
            else:
                line = []
                line.append(repository)
                line.append(quarantine_date)
                line.append(date_cleared)
                line.append(path_name)
                line.append(format)
                line.append(quarantined)
                line.append()
                line.append()
                line.append()
                writer.writerow(line)

    return


def main():

    init_report()
    list_report("quarantined_components", "firewall/components/quarantined")


if __name__ == '__main__':
    main()