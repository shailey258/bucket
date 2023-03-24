import json
import csv
import os
import shutil
import sys
import requests
import argparse
import ldap


outputDir = './output'
iqapi = 'api/v2'
rolesDb = {}

ldap_host = "ldap://ldap.forumsys.com"
ldap_user = 'cn=read-only-admin,dc=example,dc=com'
ldap_pwd = 'password'
ldap_user_basedn = "dc=example,dc=com"
ldap_user_filter = '(&(objectClass=inetOrgPerson)(uid={username}))'

def init():

    global iqurl, iquser, iqpwd, makecsv, ldap_conn, ldap_result, debug

    parser = argparse.ArgumentParser(description='Manage your Nexus IQ tokens')

    parser.add_argument('-s', '--server', default='http://localhost:8070', help='', required=False)
    parser.add_argument('-u', '--user', default='admin', help='', required=False)
    parser.add_argument('-p', '--passwd', default='admin123', required=False)
    parser.add_argument('-d', '--debug', action="store_true", required=False)

    args = vars(parser.parse_args())

    iqurl = args['server']
    iquser = args['user']
    iqpwd = args['passwd']
    debug = args['debug']

    ldap_conn, ldap_result = ldap_connect()

    return


def getNexusIqData(end_point):
    url = "{}/{}/{}" . format(iqurl, iqapi, end_point)
    # print(url)

    req = requests.get(url, auth=(iquser, iqpwd), verify=False)

    if req.status_code == 200:
        res = req.json()
    else:
        res = "Error fetching data"

    return req.status_code, res


def ldap_connect():

    conn = ldap.initialize(ldap_host)
    conn.protocol_version = 3
    conn.set_option(ldap.OPT_REFERRALS, 0)

    result = True

    try:
        conn.simple_bind_s(ldap_user, ldap_pwd)
        print ("Succesfully authenticated to ldap")
    except ldap.SERVER_DOWN:
        return "Server down", False
    except (ldap.INVALID_CREDENTIALS):
        return "Invalid credentials", False
    except ldap.LDAPError as e:
         if type(e.message) == dict and e.message.has_key('desc'):
            return "Other LDAP error: " + e.message['desc'], False
         else:
             return "Other LDAP error: " + e, False

    return conn, result


def getRoles():
    status_code, roles =  getNexusIqData('roles')

    for role in roles["roles"]:
        id = role["id"]
        name = role["name"]
        rolesDb[id] = name

    return roles


def makeReport(obj, data):
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
                oaname = d["name"]

                # if application
                # publicId = d["publicId"]
                # organizationId = d["organizationId"]

                endpoint = "{}/{}/{}" . format("roleMemberships", obj, id)

                status_code, rolesdata = getNexusIqData(endpoint)

                if debug:
                    print_jsonfile("organization_" + oaname, rolesdata)

                for role in rolesdata["memberMappings"]:
                    roleName = rolesDb.get(role["roleId"])
                    members = getRoleMmebers(role)

                    line = []
                    line.append(oaname)
                    line.append(roleName)
                    line.append(members)

                    writer.writerow(line)

    print(output_file)

    return


def getRoleMmebers(data):
    members = ""

    for m in data["members"]:
        userOrGroupName = m["userOrGroupName"]
        userFullname = getUserFullname(userOrGroupName)
        members += str(userFullname) + ","

    members = members[:-1]

    return members

def getUserFullname(userId):
    fullname = ""
    endpoint = "{}/{}" . format("users", userId)
    status_code, userdata = getNexusIqData(endpoint)

    if status_code == 200:
        firstName = userdata['firstName']
        lastName = userdata['lastName']
        email = userdata['email']
        fullname = "{} {}".format(firstName, lastName)
    else:
        fullname = getUsernameLdap(userId)

    return fullname


def getUsernameLdap(userId):
    # https://gist.github.com/dangtrinhnt/28ef75299618a1b52cf887592220489f

    fullname = userId #return the id if not found in ldap

    if ldap_result:
        ldap_filter = ldap_user_filter.replace('{username}', userId)
        results = ldap_conn.search_s(ldap_user_basedn, ldap.SCOPE_SUBTREE, ldap_filter)

        if results:
            for dn, others in results:
                fullname = others['cn'][0].decode()

    return fullname


def print_jsonfile(jsonfile, json_data):
    if debug:
        output_file = "{}/{}{}".format(outputDir, jsonfile, ".json")
        json_formatted = json.dumps(json_data, indent=2)

        with open(output_file, 'w') as outfile:
            json.dump(json_data, outfile, indent=2)

        print(output_file)

    return


def main():
    init()

    if os.path.exists(outputDir):
        shutil.rmtree(outputDir)

    os.mkdir(outputDir)

    roles = getRoles()
    print_jsonfile("roles", roles)

    status_code, organizations = getNexusIqData('organizations')
    print_jsonfile("organizations", organizations)
    makeReport("organization", organizations["organizations"])

    status_code, applications = getNexusIqData('applications')
    print_jsonfile("applications", applications)
    makeReport("application", applications["applications"])


if __name__ == '__main__':
    main()