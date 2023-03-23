import json
import csv
import os
import shutil
import sys
import requests

iqurl = sys.argv[1]
iquser = sys.argv[2]
iqpwd = sys.argv[3]

outputDir = './output'
iqapi = 'api/v2'
rolesDb = {}


def getNexusIqData2(end_point):
    
    url = "{}/{}/{}" . format(iqurl, iqapi, end_point)
    print(url)
   
    try:
        req = requests.get(url, auth=(iquser, iqpwd), verify=False)
        req.raise_for_status()

        if req.status_code == 200:
            res = req.json()
        else:
            res = "Error fetching data"
    
    except requests.exceptions.RequestException as e:  
        print("Exiting RequestException...")
        raise
    except requests.exceptions.HTTPError as e:
        raise
        print("Exiting HTTPError...")

    return req.status_code,  req.json()

def getNexusIqData(end_point):
    url = "{}/{}/{}" . format(iqurl, iqapi, end_point)
    # print(url)
   
    req = requests.get(url, auth=(iquser, iqpwd), verify=False)

    if req.status_code == 200:
        res = req.json()
    else:
        res = "Error fetching data"

    return req.status_code, res


def getRoles():
    status_code, roles =  getNexusIqData('roles')

    for role in roles["roles"]:
        id = role["id"]
        name = role["name"]
        rolesDb[id] = name

    return roles


def getReport(obj, data):
    output_file = "{}/{}{}".format(outputDir, obj, ".csv")


    with open(output_file, 'w') as fd:
            writer = csv.writer(fd)

            line = []
            line.append("Name")
            line.append("Role")
            line.append("Members")

            writer.writerow(line)

            for d in data:
                id = d["id"]
                name = d["name"]

                # if application
                # publicId = d["publicId"]
                # organizationId = d["organizationId"]

                line = []
                line.append(name)

                endpoint = "{}/{}/{}" . format("roleMemberships", obj, id)

                status_code, rolesdata = getNexusIqData(endpoint)
                role, ug = getRolesAndUsers(rolesdata["memberMappings"])

                line.append(role)
                line.append(ug)
                
                writer.writerow(line)

    print(output_file)

    return


def getRolesAndUsers(data):
    ug = ""

    for d in data:
        role = rolesDb.get(d["roleId"]) 

        for m in d["members"]:
            userOrGroupName = m["userOrGroupName"]
            userFullname = getUsername(userOrGroupName)

            # ug += userOrGroupName + ","
            ug += userFullname + ","

    ug = ug[:-1]

    return role, ug


def getUsername(userId):
    fullname = ""
    endpoint = "{}/{}" . format("users", userId)
    status_code, userdata = getNexusIqData(endpoint)

    if status_code == 200:
        firstName = userdata['firstName']
        lastName = userdata['lastName']
        email = userdata['email']
        fullname = "{} {}".format(firstName, lastName)
    else:
        fullname = getLdapUser(userId)

    return fullname


def getLdapUser(userId):
    return "Ldap User"


def print_jsonfile(jsonfile, json_data):
    output_file = "{}/{}{}".format(outputDir, jsonfile, ".json")
    json_formatted = json.dumps(json_data, indent=2)

    with open(output_file, 'w') as outfile:
        json.dump(json_data, outfile, indent=2)

    print(output_file)
    return



def main():

    if os.path.exists(outputDir):
        shutil.rmtree(outputDir)

    os.mkdir(outputDir)

    roles = getRoles()
    print_jsonfile("roles", roles)

    status_code, organizations = getNexusIqData('organizations')
    print_jsonfile("organizations", organizations)
    getReport("organization", organizations["organizations"])

    status_code, applications = getNexusIqData('applications')
    print_jsonfile("applications", applications)
    getReport("application", applications["applications"])


if __name__ == '__main__':
    main()