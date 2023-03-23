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

AD_USER_BASEDN = "dc=example,dc=com"
AD_USER_FILTER = '(&(objectClass=inetOrgPerson)(uid={username}))'
AD_GROUP_FILTER = '(&(objectClass=groupOfUniqueNames)(ou={group_name}))'
# https://gist.github.com/dangtrinhnt/28ef75299618a1b52cf887592220489f

def get_args():
    
    global iqurl, iquser, iqpwd, makecsv

    parser = argparse.ArgumentParser(description='Manage your Nexus IQ tokens')

    parser.add_argument('-s', '--server', default='http://localhost:8070', help='', required=False)
    parser.add_argument('-u', '--user', default='admin', help='', required=False)
    parser.add_argument('-p', '--passwd', default='admin123', required=False)
    parser.add_argument('--makecsv', action="store_true", required=False) 

    args = vars(parser.parse_args())

    iqurl = args['server']
    iquser = args['user']
    iqpwd = args['passwd']
    makecsv = args['makecsv']
   
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


def getCsvReport(obj, data):
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


def get_group_members(group_name, ad_conn, basedn=AD_USER_BASEDN):
    members = []
    ad_filter = AD_GROUP_FILTER.replace('{group_name}', group_name)
    
    result = ad_conn.search_s(basedn, ldap.SCOPE_SUBTREE, ad_filter)
    if result:
        print(result)
        if len(result[0]) >= 2 and 'member' in result[0][1]:
            members_tmp = result[0][1]['member']
            for m in members_tmp:
                email = get_email_by_dn(m, ad_conn)
                if email:
                    members.append(email)
    else:
        print('No members')

    return members

def get_dn_by_username(username, ad_conn, basedn=AD_USER_BASEDN):
    return_dn = ''
    ad_filter = AD_USER_FILTER.replace('{username}', username)
    results = ad_conn.search_s(basedn, ldap.SCOPE_SUBTREE, ad_filter)
    if results:
        print(results)
        for dn, others in results:
            return_dn = dn
    else:
        print('No user found')

    return return_dn

def get_email_by_dn(dn, ad_conn):
    email = ''
    result = ad_conn.search_s(dn, ldap.SCOPE_BASE, \
		'(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))')
    if result:
        for dn, attrb in result:
            if 'mail' in attrb and attrb['mail']:
                email = attrb['mail'][0].lower()
                break

    return email


def print_jsonfile(jsonfile, json_data):
    output_file = "{}/{}{}".format(outputDir, jsonfile, ".json")
    json_formatted = json.dumps(json_data, indent=2)

    with open(output_file, 'w') as outfile:
        json.dump(json_data, outfile, indent=2)

    print(output_file)
    return



def main():

    get_args()

    ldap_conn, result = ldap_connect()
    group_name = 'mathematicians'
    
    if result:
        group_members = get_group_members(group_name, ldap_conn)
        for m in group_members:
            print(m)

    user_dn = 'euclid'
    dn = get_dn_by_username(user_dn, ldap_conn)

    if os.path.exists(outputDir):
        shutil.rmtree(outputDir)

    os.mkdir(outputDir)

    roles = getRoles()
    print_jsonfile("roles", roles)

    status_code, organizations = getNexusIqData('organizations')
    print_jsonfile("organizations", organizations)
    getCsvReport("organization", organizations["organizations"])

    # status_code, applications = getNexusIqData('applications')
    # print_jsonfile("applications", applications)
    # getCsvReport("application", applications["applications"])


if __name__ == '__main__':
    main()